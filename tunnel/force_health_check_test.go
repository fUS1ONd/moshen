package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Тесты бьют в публичный шов фичи — форс-чек tunnel-пакета — и проверяют
// наблюдаемое поведение: кого и сколько раз залп попросил провериться.

// fakeProvider — провайдер, умеющий форс-чек и фиксирующий факты проверок.
// Встроенный интерфейс оставлен nil намеренно: методов сверх проверки живости
// и выдачи нод залп не касается, а вызов любого другого сразу упадёт паникой и
// покажет, что код полез не туда.
type fakeProvider struct {
	P.ProxyProvider
	name    string
	nodes   []C.Proxy
	forced  atomic.Int32
	checked atomic.Int32
}

func (p *fakeProvider) Name() string       { return p.name }
func (p *fakeProvider) Proxies() []C.Proxy { return p.nodes }
func (p *fakeProvider) HealthCheck()       { p.checked.Add(1) }
func (p *fakeProvider) ForceHealthCheck()  { p.forced.Add(1) }

// plainProvider — провайдер без поддержки форс-чека: чужая реализация
// P.ProxyProvider, которая ничего не знает про смену сети.
type plainProvider struct {
	P.ProxyProvider
	checked atomic.Int32
}

func (p *plainProvider) Proxies() []C.Proxy { return nil }
func (p *plainProvider) HealthCheck()       { p.checked.Add(1) }

// fakeGroupAdapter — адаптер группы: отдаёт свои провайдеры залпу и считает
// сбросы счётчика неудач.
type fakeGroupAdapter struct {
	C.ProxyAdapter
	name      string
	providers []P.ProxyProvider
	reset     atomic.Int32
}

func (g *fakeGroupAdapter) Name() string        { return g.name }
func (g *fakeGroupAdapter) Type() C.AdapterType { return C.Fallback }
func (g *fakeGroupAdapter) HealthCheckProviders() []P.ProxyProvider {
	return g.providers
}
func (g *fakeGroupAdapter) ResetFailedState()                { g.reset.Add(1) }
func (g *fakeGroupAdapter) Addr() string                     { return "" }
func (g *fakeGroupAdapter) SupportUDP() bool                 { return false }
func (g *fakeGroupAdapter) SupportUOT() bool                 { return false }
func (g *fakeGroupAdapter) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

// fakeProxy — прокси поверх заданного адаптера.
type fakeProxy struct {
	C.Proxy
	adapter C.ProxyAdapter
	addr    string
	typ     C.AdapterType
}

func (p *fakeProxy) Adapter() C.ProxyAdapter { return p.adapter }
func (p *fakeProxy) Addr() string            { return p.addr }
func (p *fakeProxy) Type() C.AdapterType     { return p.typ }
func (p *fakeProxy) Name() string            { return p.adapter.Name() }

// leafAdapter — обычная нода: собственный адрес, группой не является.
type leafAdapter struct {
	C.ProxyAdapter
	name string
	addr string
}

func (a *leafAdapter) Name() string { return a.name }
func (a *leafAdapter) Addr() string { return a.addr }

func leafProxy(name, addr string) *fakeProxy {
	return &fakeProxy{adapter: &leafAdapter{name: name, addr: addr}, typ: C.Vless, addr: addr}
}

// setTunnelState подменяет карты прокси и провайдеров на время теста.
func setTunnelState(t *testing.T, newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider) {
	t.Helper()

	configMux.RLock()
	oldProxies, oldProviders := proxies, providers
	configMux.RUnlock()

	UpdateProxies(newProxies, newProviders)
	t.Cleanup(func() { UpdateProxies(oldProxies, oldProviders) })

	// Дебаунс глобального чекера переживает границу теста: без сброса сигнал
	// следующего теста схлопнулся бы с сигналом предыдущего.
	defaultForceChecker.mu.Lock()
	defaultForceChecker.lastTrigger = time.Time{}
	defaultForceChecker.mu.Unlock()
}

// waitFor ждёт выполнения условия: залп асинхронный, результат появляется не в
// момент возврата из вызова.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func TestForceHealthCheckAllProbesProvidersAndGroups(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	group := &fakeGroupAdapter{name: "group"}
	// Листовых нод в состоянии нет намеренно: гейт готовности проверяется
	// отдельными тестами со своим дозвоном, здесь важен только залп.
	setTunnelState(t,
		map[string]C.Proxy{"group": &fakeProxy{adapter: group, typ: C.Fallback}},
		map[string]P.ProxyProvider{"provider": provider},
	)

	ForceHealthCheckAll()

	waitFor(t, func() bool { return provider.forced.Load() == 1 }, "форс-чек провайдера")
	waitFor(t, func() bool { return group.reset.Load() == 1 }, "сброс счётчика неудач группы")

	if got := provider.checked.Load(); got != 0 {
		t.Fatalf("провайдер проверен штатным путём %d раз, ожидался только форс-чек", got)
	}
}

// Провайдер, на который ссылаются сразу несколько групп, форсится один раз, а
// не по разу на группу: иначе залп превращается в шторм проб по всем нодам.
func TestForceHealthCheckAllForcesSharedProviderOnce(t *testing.T) {
	shared := &fakeProvider{name: "shared"}
	own := &fakeProvider{name: "own"}
	groupA := &fakeGroupAdapter{name: "a", providers: []P.ProxyProvider{shared}}
	groupB := &fakeGroupAdapter{name: "b", providers: []P.ProxyProvider{shared}}
	// groupC живёт на собственном compatible-провайдере: в общей карте его нет,
	// и увидеть его залп может только через саму группу.
	groupC := &fakeGroupAdapter{name: "c", providers: []P.ProxyProvider{own}}

	setTunnelState(t,
		map[string]C.Proxy{
			"a": &fakeProxy{adapter: groupA, typ: C.Fallback},
			"b": &fakeProxy{adapter: groupB, typ: C.Fallback},
			"c": &fakeProxy{adapter: groupC, typ: C.Fallback},
		},
		map[string]P.ProxyProvider{"shared": shared},
	)

	ForceHealthCheckAll()

	waitFor(t, func() bool { return shared.forced.Load() >= 1 }, "форс-чек общего провайдера")
	waitFor(t, func() bool { return own.forced.Load() >= 1 }, "форс-чек собственного провайдера группы")
	time.Sleep(50 * time.Millisecond)

	if got := shared.forced.Load(); got != 1 {
		t.Fatalf("общий провайдер форсили %d раз, ожидался ровно один", got)
	}
	if got := own.forced.Load(); got != 1 {
		t.Fatalf("собственный провайдер группы форсили %d раз, ожидался ровно один", got)
	}
}

func TestForceHealthCheckAllFallsBackToPlainHealthCheck(t *testing.T) {
	provider := &plainProvider{}
	setTunnelState(t, map[string]C.Proxy{}, map[string]P.ProxyProvider{"provider": provider})

	ForceHealthCheckAll()

	waitFor(t, func() bool { return provider.checked.Load() == 1 }, "штатная проверка провайдера без форс-чека")
}

// fakeDialer — дозвон гейта: фиксирует адреса проб и отвечает по сценарию.
type fakeDialer struct {
	mu        sync.Mutex
	addrs     []string
	reachable bool
}

func (d *fakeDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	reachable := d.reachable
	d.mu.Unlock()

	if !reachable {
		return nil, errors.New("сеть недоступна")
	}
	// Гейт закрывает соединение, поэтому нужна настоящая пара сокетов.
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (d *fakeDialer) probed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// gateChecker — чекер с ужатыми таймингами: тест не должен ждать секунды.
func gateChecker(dial *fakeDialer) *forceChecker {
	return &forceChecker{
		debounce:    time.Second,
		timeout:     300 * time.Millisecond,
		interval:    20 * time.Millisecond,
		dialTimeout: 50 * time.Millisecond,
		probeLimit:  readinessProbeLimit,
		dial:        dial.dial,
	}
}

// Путь ожил — второй залп идёт сразу, а не по потолку ожидания.
func TestReadinessGateFiresSecondVolleyOnFirstReachableProbe(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	setTunnelState(t,
		map[string]C.Proxy{"node": leafProxy("node", "example.com:443")},
		map[string]P.ProxyProvider{"provider": provider},
	)

	dial := &fakeDialer{reachable: true}
	checker := gateChecker(dial)

	start := time.Now()
	checker.trigger()

	waitFor(t, func() bool { return provider.forced.Load() == 2 }, "второй залп по готовности пути")
	if elapsed := time.Since(start); elapsed >= checker.timeout {
		t.Fatalf("второй залп ждал %s, то есть дотянул до потолка вместо выхода по первому успеху", elapsed)
	}
}

// Сети нет — второй залп всё равно идёт, по потолку ожидания.
func TestReadinessGateFiresSecondVolleyOnTimeout(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	setTunnelState(t,
		map[string]C.Proxy{"node": leafProxy("node", "example.com:443")},
		map[string]P.ProxyProvider{"provider": provider},
	)

	dial := &fakeDialer{reachable: false}
	checker := gateChecker(dial)

	start := time.Now()
	checker.trigger()

	waitFor(t, func() bool { return provider.forced.Load() == 2 }, "второй залп по потолку ожидания")
	if elapsed := time.Since(start); elapsed < checker.timeout {
		t.Fatalf("второй залп пришёл через %s, раньше потолка %s", elapsed, checker.timeout)
	}
}

// Ноды подписки лежат только в провайдере, в общей карте прокси их нет. Гейт
// обязан дозваниваться и до них — иначе на subscription-конфиге второго залпа
// не будет вовсе.
func TestReadinessGateProbesProviderNodes(t *testing.T) {
	provider := &fakeProvider{
		name:  "sub",
		nodes: []C.Proxy{leafProxy("sub-1", "sub1.example:443")},
	}
	group := &fakeGroupAdapter{name: "group", providers: []P.ProxyProvider{provider}}
	setTunnelState(t,
		map[string]C.Proxy{"group": &fakeProxy{adapter: group, typ: C.Fallback}},
		map[string]P.ProxyProvider{"sub": provider},
	)

	dial := &fakeDialer{reachable: true}
	checker := gateChecker(dial)
	checker.trigger()

	waitFor(t, func() bool { return provider.forced.Load() == 2 }, "второй залп по нодам провайдера")

	probed := dial.probed()
	if len(probed) == 0 || probed[0] != "sub1.example:443" {
		t.Fatalf("гейт дозванивался до %v, ожидался адрес ноды из провайдера", probed)
	}
}

// Повторная смена сети отменяет недоигранную реакцию на предыдущую.
func TestReadinessGateCancelledByNewerGeneration(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	setTunnelState(t,
		map[string]C.Proxy{"node": leafProxy("node", "example.com:443")},
		map[string]P.ProxyProvider{"provider": provider},
	)

	dial := &fakeDialer{reachable: false}
	checker := gateChecker(dial)
	// Дебаунс ужат: нужен именно второй принятый сигнал, а не подавленный.
	checker.debounce = 10 * time.Millisecond

	checker.trigger()
	time.Sleep(3 * checker.interval)
	checker.trigger()

	// Два немедленных залпа плюс один гейтовый — от последнего поколения.
	waitFor(t, func() bool { return provider.forced.Load() == 3 }, "залп гейта последнего поколения")
	time.Sleep(2 * checker.timeout)

	if got := provider.forced.Load(); got != 3 {
		t.Fatalf("залпов: %d, ожидалось 3 (два немедленных и один гейтовый) — гейт отменённого поколения выстрелил", got)
	}
}

// Дозваниваться нужно только до нод: у групп адреса нет, служебные адаптеры до
// серверов не ходят, пустой адрес дозвону не поддаётся.
func TestReadinessGateProbesOnlyLeafProxies(t *testing.T) {
	setTunnelState(t,
		map[string]C.Proxy{
			"direct":  &fakeProxy{adapter: &leafAdapter{name: "direct", addr: ""}, typ: C.Direct},
			"reject":  &fakeProxy{adapter: &leafAdapter{name: "reject", addr: ""}, typ: C.Reject},
			"group":   &fakeProxy{adapter: &fakeGroupAdapter{name: "group"}, typ: C.Fallback},
			"noaddr":  &fakeProxy{adapter: &leafAdapter{name: "noaddr", addr: ""}, typ: C.Vless},
			"node":    leafProxy("node", "example.com:443"),
			"nodedup": leafProxy("nodedup", "example.com:443"),
		},
		map[string]P.ProxyProvider{},
	)

	dial := &fakeDialer{reachable: true}
	checker := gateChecker(dial)
	checker.trigger()

	waitFor(t, func() bool { return len(dial.probed()) > 0 }, "проба гейта")
	time.Sleep(2 * checker.interval)

	probed := dial.probed()
	for _, addr := range probed {
		if addr != "example.com:443" {
			t.Fatalf("гейт дозванивался до %q, а должен только до нод с собственным адресом", addr)
		}
	}
	if len(probed) != 1 {
		t.Fatalf("проб: %d (%v), ожидалась одна — адреса-дубликаты опрашивать незачем", len(probed), probed)
	}
}

func TestForceCheckDebounceCollapsesBurst(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	setTunnelState(t, map[string]C.Proxy{}, map[string]P.ProxyProvider{"provider": provider})

	debounce := 150 * time.Millisecond
	checker := &forceChecker{debounce: debounce}

	// Пачка сигналов (флап сети) — один залп.
	checker.trigger()
	checker.trigger()
	checker.trigger()

	waitFor(t, func() bool { return provider.forced.Load() == 1 }, "первый залп")
	time.Sleep(debounce / 2)
	if got := provider.forced.Load(); got != 1 {
		t.Fatalf("залпов в окне дебаунса: %d, ожидался 1", got)
	}

	// Сигнал за окном дебаунса — новый залп.
	time.Sleep(debounce)
	checker.trigger()
	waitFor(t, func() bool { return provider.forced.Load() == 2 }, "залп после окна дебаунса")
}
