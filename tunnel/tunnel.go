package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/nat"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"golang.org/x/exp/slices"
)

const (
	queueCapacity  = 64  // chan capacity tcpQueue and udpQueue
	senderCapacity = 128 // chan capacity of PacketSender
)

var (
	status        = atomic.NewInt32Enum(Suspend)
	udpInit       sync.Once
	udpQueues     []chan C.PacketAdapter
	natTable      = nat.New()
	rules         []C.Rule
	listeners     = make(map[string]C.InboundListener)
	subRules      map[string][]C.Rule
	proxies       = make(map[string]C.Proxy)
	providers     map[string]P.ProxyProvider
	ruleProviders map[string]P.RuleProvider
	configMux     sync.RWMutex

	// for compatibility, lazy init
	tcpQueue  chan C.ConnContext
	tcpInOnce sync.Once
	udpQueue  chan C.PacketAdapter
	udpInOnce sync.Once

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode = atomic.NewInt32Enum(process.FindProcessStrict)

	snifferDispatcher *sniffer.Dispatcher
	sniffingEnable    = false

	ruleUpdateCallback = utils.NewCallback[P.RuleProvider]()

	countryCodeRegex = regexp.MustCompile(`(?i)^[A-Z]{2}$`)
)

type tunnel struct{}

var Tunnel = tunnel{}
var _ C.Tunnel = Tunnel
var _ P.Tunnel = Tunnel
var _ proxydialer.Tunnel = Tunnel

func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	connCtx := icontext.NewConnContext(conn, metadata)
	handleTCPConn(connCtx)
}

func initUDP() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}

	udpQueues = make([]chan C.PacketAdapter, numUDPWorkers)
	for i := 0; i < numUDPWorkers; i++ {
		queue := make(chan C.PacketAdapter, queueCapacity)
		udpQueues[i] = queue
		go processUDP(queue)
	}
}

func (t tunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	udpInit.Do(initUDP)

	packetAdapter := C.NewPacketAdapter(packet, metadata)
	key := packetAdapter.Key()

	hash := utils.MapHash(key)
	queueNo := uint(hash) % uint(len(udpQueues))

	select {
	case udpQueues[queueNo] <- packetAdapter:
	default:
		packet.Drop()
	}
}

func (t tunnel) NatTable() C.NatTable {
	return natTable
}

func (t tunnel) Proxies() map[string]C.Proxy {
	return proxies
}

func (t tunnel) Providers() map[string]P.ProxyProvider {
	return providers
}

func (t tunnel) RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

func (t tunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return ruleUpdateCallback
}

func OnSuspend() {
	status.Store(Suspend)
}

func OnInnerLoading() {
	status.Store(Inner)
}

func OnRunning() {
	status.Store(Running)
}

func Status() TunnelStatus {
	return status.Load()
}

func SetSniffing(b bool) {
	if snifferDispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable
}

// TCPIn return fan-in queue
// Deprecated: using Tunnel instead
func TCPIn() chan<- C.ConnContext {
	tcpInOnce.Do(func() {
		tcpQueue = make(chan C.ConnContext, queueCapacity)
		go func() {
			for connCtx := range tcpQueue {
				go handleTCPConn(connCtx)
			}
		}()
	})
	return tcpQueue
}

// UDPIn return fan-in udp queue
// Deprecated: using Tunnel instead
func UDPIn() chan<- C.PacketAdapter {
	udpInOnce.Do(func() {
		udpQueue = make(chan C.PacketAdapter, queueCapacity)
		go func() {
			for packet := range udpQueue {
				Tunnel.HandleUDPPacket(packet, packet.Metadata())
			}
		}()
	})
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

func Listeners() map[string]C.InboundListener {
	return listeners
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]P.RuleProvider) {
	configMux.Lock()
	rules = newRules
	ruleProviders = rp
	subRules = newSubRule
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]P.ProxyProvider {
	return providers
}

// RuleProviders return all loaded rule providers
func RuleProviders() map[string]P.RuleProvider {
	return ruleProviders
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

// forceHealthChecker — провайдер или группа, умеющие проверить живость немедленно,
// вне штатного расписания и в обход окна дедупликации. Интерфейс объявлен здесь,
// у потребителя: расширять ради одного метода публичный P.ProxyProvider не нужно,
// а type assertion оставляет чужие реализации рабочими (они получат штатную
// проверку вместо форсированной).
type forceHealthChecker interface {
	ForceHealthCheck()
}

// groupHealthChecker — группа прокси: отдаёт залпу свои провайдеры и умеет
// сбросить счётчик неудач. Объявлен здесь, у потребителя, по той же причине:
// расширять публичные интерфейсы адаптеров ради двух методов не нужно, а type
// assertion оставляет чужие реализации рабочими.
//
// Провайдеры группы форсит сам залп, а не группа: только у залпа есть полная
// картина, и только он может не форсить один и тот же провайдер по разу на
// каждую ссылающуюся группу.
type groupHealthChecker interface {
	HealthCheckProviders() []P.ProxyProvider
	ResetFailedState()
}

// Тайминги форс-чека. Подобраны на стенде со сменой сети на LTE-модеме и
// намеренно не выносятся в конфиг: фича работает из коробки, без рубильников.
const (
	// Окно схлопывания входных сигналов. На границе покрытия Wi-Fi сеть флапает
	// и сигналы приходят пачкой; без дебаунса каждый стоил бы залпа проб по всем
	// нодам. Реактивность не страдает: подавленный сигнал догонит вторым залпом,
	// который даёт гейт готовности.
	forceCheckDebounce = time.Second

	// Потолок ожидания готовности пути. За три секунды новый путь либо поднялся,
	// либо сети нет вовсе — дальше ждать нечего, второй залп идёт безусловно.
	readinessTimeout = 3 * time.Second

	// Пауза между попытками дозвона. Реже — теряем секунды на ровном месте,
	// чаще — жжём батарею и мобильный канал.
	readinessInterval = 250 * time.Millisecond

	// Таймаут одного дозвона: с запасом к RTT мобильной сети, но заметно меньше
	// потолка, чтобы за него уместилось несколько попыток.
	readinessDialTimeout = 500 * time.Millisecond

	// Сколько адресов опрашивает гейт. В конфиге бывают сотни нод, и дозвон до
	// каждой каждые 250 мс — это шторм. Гейту хватает горсти: он выясняет не
	// «жива ли конкретная нода», а «проходит ли через новый путь вообще TCP».
	readinessProbeLimit = 8
)

// forceChecker — механика форс-чека: дебаунс входных сигналов, залп проверок,
// гейт готовности и поколения. Отдельным типом, а не набором пакетных
// переменных, чтобы тесты могли собрать свой экземпляр с ужатыми таймингами и
// фейковым дозвоном, не трогая рабочий.
type forceChecker struct {
	debounce    time.Duration
	timeout     time.Duration
	interval    time.Duration
	dialTimeout time.Duration
	probeLimit  int

	// dial — дозвон гейта готовности. По умолчанию component/dialer: он
	// привязывает сокет к физическому интерфейсу, поэтому проба не заворачивается
	// в наш же туннель. Голый net.Dial при включённом auto-route дал бы ложный
	// успех через себя же — гейт открывался бы, не дождавшись реальной сети.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	// gen — поколение форс-чека. Свежий сигнал инкрементирует счётчик и тем
	// самым отменяет незавершённый гейт предыдущего: одновременно живёт только
	// реакция последнего поколения, эффекты не накладываются.
	gen atomic.Int64

	mu          sync.Mutex
	lastTrigger time.Time
}

// defaultForceChecker обслуживает публичный ForceHealthCheckAll.
var defaultForceChecker = &forceChecker{
	debounce:    forceCheckDebounce,
	timeout:     readinessTimeout,
	interval:    readinessInterval,
	dialTimeout: readinessDialTimeout,
	probeLimit:  readinessProbeLimit,
	dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	},
}

// ForceHealthCheckAll — немедленная проверка живости всех прокси и групп.
// Единственный публичный вход быстрого переключения: его дёргают монитор
// дефолтного интерфейса (десктоп, TUN) и Android-клиент при смене сети,
// поднятии туннеля и включении экрана.
//
// Зачем: alive-состояния прокси остаются от прежнего сетевого пути, и до
// очередного тика health-check (в конфигах пользователей это десятки секунд)
// ядро льёт трафик в заведомо мёртвый путь.
//
// Вызов не блокирует вызывающего: приходит из системного callback'а, держать
// его на время проб нельзя.
func ForceHealthCheckAll() {
	defaultForceChecker.trigger()
}

// trigger — реакция на один входной сигнал смены сети: залп сразу и второй
// залп по готовности нового пути.
func (fc *forceChecker) trigger() {
	if !fc.acceptTrigger() {
		// Сигнал схлопнут дебаунсом. Своего поколения он не заводит: поколение
		// отменяет недоигранный гейт предыдущего, и при флапе на границе
		// покрытия пачка подавленных сигналов сносила бы гейт за гейтом — второй
		// залп, ради которого гейт и существует, не случался бы ни разу.
		// Реакция уже идёт, её гейт даст второй залп за всю пачку.
		return
	}
	gen := fc.gen.Add(1)
	fc.fireVolley()
	go fc.awaitReadiness(gen)
}

// acceptTrigger — дебаунс входных сигналов: пачка событий флапа схлопывается в
// один залп. Считается по сигналам, а не по залпам, — залпы бывают и полезные
// (второй залп за гейтом готовности), глушить их дебаунсом нельзя.
func (fc *forceChecker) acceptTrigger() bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	now := time.Now()
	if !fc.lastTrigger.IsZero() && now.Sub(fc.lastTrigger) < fc.debounce {
		return false
	}
	fc.lastTrigger = now
	return true
}

// fireVolley — залп: проверка живости всех провайдеров и групп разом, каждая
// цель в своей горутине. Группы проверяются отдельно от провайдеров, потому что
// у группы со списком proxies провайдер собственный, в общей карте его нет.
func (fc *forceChecker) fireVolley() {
	configMux.RLock()
	currentProviders := providers
	currentProxies := proxies
	configMux.RUnlock()

	// Один и тот же провайдер виден и в общей карте, и через каждую группу с
	// use:. Форсим по идентичности ровно один раз: иначе залп множился бы на
	// число групп и вместо ускорения давал шторм проб по всем нодам подписки.
	seen := make(map[P.ProxyProvider]struct{}, len(currentProviders))
	forceOnce := func(provider P.ProxyProvider) {
		if provider == nil {
			return
		}
		if _, dup := seen[provider]; dup {
			return
		}
		seen[provider] = struct{}{}
		go forceProviderHealthCheck(provider)
	}

	for _, provider := range currentProviders {
		forceOnce(provider)
	}
	for _, proxy := range currentProxies {
		group, ok := proxy.Adapter().(groupHealthChecker)
		if !ok {
			continue
		}
		group.ResetFailedState()
		// Провайдер группы со списком proxies собственный, в общей карте его
		// нет — его залп видит только отсюда.
		for _, provider := range group.HealthCheckProviders() {
			forceOnce(provider)
		}
	}
}

// forceProviderHealthCheck — проверка провайдера в обход окна дедупликации, если
// он это умеет. Иначе штатная: проверить с дедупликацией лучше, чем не проверить.
func forceProviderHealthCheck(provider P.ProxyProvider) {
	if forceable, ok := provider.(forceHealthChecker); ok {
		forceable.ForceHealthCheck()
		return
	}
	provider.HealthCheck()
}

// awaitReadiness ждёт, пока новый сетевой путь начнёт пропускать трафик, и даёт
// второй залп.
//
// Зачем второй залп: первый уходит в момент, когда система уже сообщила о смене
// сети, а новый путь ещё поднимается. Пробы по нему не доходят, живые ноды
// получают ложное «мёртв» — и группа откатывается на заведомо дохлый вариант
// ровно тогда, когда связь наконец появилась. Залп по прогретому пути это
// исправляет.
//
// Готовность — первый успешный TCP-дозвон до любого из серверов нод. Не
// дождались за потолок — стреляем безусловно: если сети действительно нет, все
// ноды честно останутся мёртвыми, хуже не будет.
func (fc *forceChecker) awaitReadiness(gen int64) {
	addrs := fc.probeAddrs()
	if len(addrs) == 0 {
		return // дозваниваться некуда, второй залп ничего не уточнит
	}

	deadline := time.Now().Add(fc.timeout)
	for {
		if fc.gen.Load() != gen {
			return // сеть сменилась снова, гейтом занимается новое поколение
		}
		if fc.anyReachable(addrs) || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(fc.interval)
	}

	if fc.gen.Load() != gen {
		return
	}
	fc.fireVolley()
}

// probeAddrs — адреса для гейта: server:port листовых нод.
//
// Список сортируется и режется по потолку. Сортировка не косметика: обход карты
// в Go случаен, и без неё каждый вызов гейта опрашивал бы свою случайную горсть
// адресов — поведение фичи стало бы лотереей, невоспроизводимой на стенде.
func (fc *forceChecker) probeAddrs() []string {
	configMux.RLock()
	currentProxies := proxies
	currentProviders := providers
	configMux.RUnlock()

	seen := make(map[string]struct{}, fc.probeLimit)
	addrs := make([]string, 0, fc.probeLimit)

	// add возвращает false, когда потолок набран и обход пора прекращать.
	add := func(proxy C.Proxy) bool {
		if proxy == nil || !isLeafProxy(proxy) {
			return true
		}
		addr := proxy.Addr()
		if addr == "" {
			return true
		}
		if _, dup := seen[addr]; dup {
			return true
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
		return len(addrs) < fc.probeLimit
	}

	names := make([]string, 0, len(currentProxies))
	for name := range currentProxies {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if !add(currentProxies[name]) {
			return addrs
		}
	}

	// Ноды подписок в общей карте прокси не лежат: туда попадают только ноды из
	// секции proxies, группы и служебные адаптеры. Без обхода провайдеров гейт
	// готовности молчал бы на самом частом мобильном конфиге (proxy-providers +
	// группы с use:) — дозваниваться было бы некуда, и второго залпа не было бы
	// вовсе.
	providerNames := make([]string, 0, len(currentProviders))
	for name := range currentProviders {
		providerNames = append(providerNames, name)
	}
	slices.Sort(providerNames)
	for _, name := range providerNames {
		for _, proxy := range currentProviders[name].Proxies() {
			if !add(proxy) {
				return addrs
			}
		}
	}

	return addrs
}

// isLeafProxy — прокси с собственным сетевым адресом: не группа и не служебный
// адаптер. У групп адреса нет, служебные (DIRECT, REJECT и прочие) до серверов
// нод не ходят — гейту и те и другие бесполезны.
func isLeafProxy(proxy C.Proxy) bool {
	switch proxy.Type() {
	case C.Direct, C.Reject, C.RejectDrop, C.Compatible, C.Pass, C.PassRule, C.Rematch, C.Dns:
		return false
	}
	// Группы опознаются по интерфейсу группы, а не по списку типов: так новый
	// тип группы у апстрима не придётся дописывать сюда руками.
	_, isGroup := proxy.Adapter().(groupHealthChecker)
	return !isGroup
}

// anyReachable — дозвон до всех адресов разом, true по первому успеху. Ждать
// остальных незачем: гейт спрашивает «путь ожил?», а не «сколько нод живо».
func (fc *forceChecker) anyReachable(addrs []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), fc.dialTimeout)
	defer cancel()

	results := make(chan bool, len(addrs))
	for _, addr := range addrs {
		addr := addr
		go func() {
			conn, err := fc.dial(ctx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
			}
			results <- err == nil
		}()
	}

	for range addrs {
		if <-results {
			return true // остальные дозвоны свернёт cancel
		}
	}
	return false
}

func UpdateListeners(newListeners map[string]C.InboundListener) {
	configMux.Lock()
	defer configMux.Unlock()
	listeners = newListeners
}

func UpdateSniffer(dispatcher *sniffer.Dispatcher) {
	configMux.Lock()
	snifferDispatcher = dispatcher
	sniffingEnable = dispatcher.Enable()
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

func FindProcessMode() process.FindProcessMode {
	return findProcessMode.Load()
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode process.FindProcessMode) {
	findProcessMode.Store(mode)
}

func isHandle(t C.Type) bool {
	status := status.Load()
	return status == Running || (status == Inner && t == C.INNER)
}

func fixMetadata(metadata *C.Metadata) {
	// first unmap dstIP
	metadata.DstIP = metadata.DstIP.Unmap()
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip.Unmap()
		metadata.Host = ""
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.IsFakeIP(metadata.DstIP) {
				// only clear dstIP if it is confirmed to be a fake IP
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node, ok := resolver.DefaultHosts.Search(host, false); ok {
				// redir-host should lookup the hosts
				metadata.DstIP, _ = node.RandIP()
			} else if node != nil && node.IsDomain {
				metadata.Host = node.Domain
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	} else if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		// try use domain mapping
		metadata.Host = node.Domain
	}

	return nil
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy]
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}
	var (
		resolved             bool
		attemptProcessLookup = metadata.Type != C.INNER
	)

	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = node.RandIP()
		resolved = true
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			if !resolved && metadata.Host != "" && !metadata.Resolved() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				ip, err := resolver.ResolveIP(ctx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				resolved = true
			}
		},
		FindProcess: func() {
			if attemptProcessLookup {
				attemptProcessLookup = false
				if !features.CMFA {
					// normal check for process
					uid, path, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort))
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = filepath.Base(path)
						metadata.ProcessPath = path
						metadata.Uid = uid

						if pkg, err := process.FindPackageName(metadata); err == nil { // for android (not CMFA) package names
							metadata.Process = pkg
						}
					}
				} else {
					// check package names
					pkg, err := process.FindPackageName(metadata)
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = pkg
					}
				}
			}
		},
		CheckPassRule: func(adapterName string) bool {
			adapter, ok := proxies[adapterName]
			if !ok {
				return false
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
	}

	switch FindProcessMode() {
	case process.FindProcessAlways:
		helper.FindProcess()
		helper.FindProcess = nil
	case process.FindProcessOff:
		helper.FindProcess = nil
	}

	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = match(metadata, helper)
	}
	return
}

// processUDP starts a loop to handle udp packet
func processUDP(queue chan C.PacketAdapter) {
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(packet C.PacketAdapter) {
	if !isHandle(packet.Metadata().Type) {
		packet.Drop()
		return
	}

	metadata := packet.Metadata()
	if !metadata.Valid() {
		packet.Drop()
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	if err := preHandleMetadata(metadata.Clone()); err != nil { // precheck without modify metadata
		packet.Drop()
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	key := packet.Key()
	sender, loaded := natTable.GetOrCreate(key, func() C.PacketSender {
		sender := newPacketSender()
		if sniffingEnable && snifferDispatcher.Enable() {
			return snifferDispatcher.UDPSniff(packet, sender)
		}
		return sender
	})
	if !loaded {
		dial := func() (C.PacketConn, C.WriteBackProxy, error) {
			originMetadata := metadata  // save origin metadata
			metadata = metadata.Clone() // don't modify PacketAdapter's metadata

			if err := sender.DoSniff(metadata); err != nil {
				log.Warnln("[UDP] DoSniff error: %s", err.Error())
				return nil, nil, err
			}

			_ = preHandleMetadata(metadata) // error was pre-checked

			proxy, rule, err := resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				return nil, nil, err
			}

			dialMetadata := metadata.Pure()
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
			defer cancel()
			rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
				return proxy.ListenPacketContext(ctx, dialMetadata)
			}, func(err error) {
				logMetadataErr(metadata, rule, proxy, err)
			})
			if err != nil {
				return nil, nil, err
			}
			logMetadata(metadata, rule, rawPc)

			// recover info to dialMetadata for smart
			dialMetadata.Host = metadata.Host
			dialMetadata.SmartTarget = metadata.SmartTarget
			dialMetadata.SmartBlock = metadata.SmartBlock

			pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, dialMetadata, rule, 0, 0, true)

			sender.AddMapping(originMetadata, dialMetadata)
			oAddrPort := dialMetadata.AddrPort()
			writeBackProxy := nat.NewWriteBackProxy(packet)

			go handleUDPToLocal(writeBackProxy, pc, sender, key, oAddrPort)
			return pc, writeBackProxy, nil
		}

		go func() {
			pc, proxy, err := dial()
			if err != nil {
				sender.Close()
				natTable.Delete(key)
				return
			}
			sender.Process(pc, proxy)
		}()
	}
	sender.Send(packet) // nonblocking
}

func handleTCPConn(connCtx C.ConnContext) {
	if !isHandle(connCtx.Metadata().Type) {
		_ = connCtx.Conn().Close()
		return
	}

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	preHandleFailed := false
	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		preHandleFailed = true
	}

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if sniffingEnable && snifferDispatcher.Enable() {
		// Try to sniff a domain when `preHandleMetadata` failed, this is usually
		// caused by a "Fake DNS record missing" error when enhanced-mode is fake-ip.
		if snifferDispatcher.TCPSniff(conn, metadata) {
			// we now have a domain name
			preHandleFailed = false
		}
	}

	// If both trials have failed, we can do nothing but give up
	if preHandleFailed {
		log.Debugln("[Metadata PreHandle] failed to sniff a domain for connection %s --> %s, give up",
			metadata.SourceDetail(), metadata.RemoteAddress())
		return
	}

	peekMutex := sync.Mutex{}
	if !conn.Peeked() {
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	proxy, rule, err := resolveMetadata(metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
			if dstIp, _ := node.RandIP(); !resolver.IsFakeIP(dstIp) {
				dialMetadata.DstIP = dstIp
				dialMetadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := retry(ctx, func(ctx context.Context) (remoteConn C.Conn, err error) {
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			return
		}

		if N.NeedHandshake(remoteConn) {
			defer func() {
				if err != nil {
					_ = remoteConn.Close()
					for _, chain := range remoteConn.Chains() {
						if chain == "REJECT" {
							err = nil
							return
						}
					}
					remoteConn = nil
				}
			}()
			peekMutex.Lock()
			defer peekMutex.Unlock()
			peekBytes, _ = conn.Peek(conn.Buffered())
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
		}
		return
	}, func(err error) {
		logMetadataErr(metadata, rule, proxy, err)
	})
	if err != nil {
		return
	}
	logMetadata(metadata, rule, remoteConn)

	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, int64(peekLen), 0, true)
	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	handleSocket(conn, remoteConn)
}

func logMetadataErr(metadata *C.Metadata, rule C.Rule, proxy C.ProxyAdapter, err error) {
	if rule == nil {
		log.Warnln("[%s] dial %s %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	} else {
		log.Warnln("[%s] dial %s (match %s/%s) %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	}
}

func logMetadata(metadata *C.Metadata, rule C.Rule, remoteConn C.Connection) {
	switch {
	case metadata.SpecialProxy != "":
		log.Infoln("[%s] %s --> %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String())
		}
	case mode == Global:
		log.Infoln("[%s] %s --> %s using GLOBAL", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[%s] %s --> %s using DIRECT", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln("[%s] %s --> %s doesn't match any rule using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	}
}

func match(metadata *C.Metadata, helper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var rematchChain []string
	for {
		var rematchProxy C.Proxy
		var rematchRule C.Rule
	GetRules:
		for _, rule := range getRules(metadata) {
			if matched, ada := rule.Match(metadata, helper); matched {
				adapter, ok := proxies[ada]
				if !ok {
					continue
				}

				// set target for Smart gorup nodes selected
				if smartRuleType(rule.RuleType()) {
					if rule.RuleType().String() != "GEOIP" || !countryCodeRegex.MatchString(rule.Payload()) {
						metadata.SmartTarget = fmt.Sprintf("%s [%s]", rule.RuleType().String(), rule.Payload())
					}
				}

				smart := false

				// parse multi-layer nesting
				for adapter := adapter; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
					if adapter.Type() == C.Smart {
						smart = true
					}
					if adapter.Type() == C.Pass {
						log.Debugln("%s match Pass rule", adapter.Name())
						continue GetRules
					}
					if adapter.Type() == C.Rematch {
						log.Debugln("%s match Rematch rule", adapter.Name())
						rematchProxy = adapter
						rematchRule = rule
						break GetRules
					}
				}

				if !smart {
					metadata.SmartTarget = ""
				} else {
					metadata.SmartBlock = "normal"
				}

				if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
					log.Debugln("%s UDP is not supported", adapter.Name())
					continue
				}

				return adapter, rule, nil
			}
		}
		if rematchProxy != nil {
			if slices.Contains(rematchChain, rematchProxy.Name()) {
				log.Warnln("[Rule] rematch cycle detected on %s", rematchProxy.Name())
				return rematchProxy, rematchRule, nil
			}
			rematchChain = append(rematchChain, rematchProxy.Name())
			conn, err := rematchProxy.DialContext(context.Background(), metadata) // not a real connection, just for metadata update
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				log.Warnln("[Rule] rematch proxy %s failed to update metadata: %s", rematchProxy.Name(), err)
				return rematchProxy, rematchRule, nil
			}
			log.Debugln("[Rule] rematch proxy %s update metadata to rematch-name=%q sub-rule=%q", rematchProxy.Name(), metadata.InName, metadata.SpecialRules)
			continue
		}
		return proxies["DIRECT"], nil, nil
	}
}

func getRules(metadata *C.Metadata) []C.Rule {
	if sr, ok := subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return rules
	}
}

func ShouldStopRetry(err error) bool {
	if errors.Is(err, resolver.ErrIPNotFound) {
		return true
	}
	if errors.Is(err, resolver.ErrIPVersion) {
		return true
	}
	if errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	if errors.Is(err, loopback.ErrReject) {
		return true
	}
	return false
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	s := slowdown.New()
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if ShouldStopRetry(err) {
				return
			}
			if s.Wait(ctx) == nil {
				continue
			} else {
				return
			}
		} else {
			break
		}
	}
	return
}

func smartRuleType(rt C.RuleType) bool {
	return C.SmartRuleTypes[rt]
}
