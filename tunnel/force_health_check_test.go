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
// залп не касается, а вызов любого другого сразу упадёт паникой и покажет, что
// код полез не туда.
type fakeProvider struct {
	P.ProxyProvider
	name    string
	forced  atomic.Int32
	checked atomic.Int32
}

func (p *fakeProvider) Name() string      { return p.name }
func (p *fakeProvider) HealthCheck()      { p.checked.Add(1) }
func (p *fakeProvider) ForceHealthCheck() { p.forced.Add(1) }

// plainProvider — провайдер без поддержки форс-чека: чужая реализация
// P.ProxyProvider, которая ничего не знает про смену сети.
type plainProvider struct {
	P.ProxyProvider
	checked atomic.Int32
}

func (p *plainProvider) HealthCheck() { p.checked.Add(1) }

// fakeGroupAdapter — адаптер группы: умеет форс-чек и считает вызовы.
type fakeGroupAdapter struct {
	C.ProxyAdapter
	name   string
	forced atomic.Int32
}

func (g *fakeGroupAdapter) Name() string                     { return g.name }
func (g *fakeGroupAdapter) Type() C.AdapterType              { return C.Fallback }
func (g *fakeGroupAdapter) ForceHealthCheck()                { g.forced.Add(1) }
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

// leafAdapter — обычная нода: собственный адрес, форс-чек не поддерживает
// (её проверяет провайдер, а не она сама).
type leafAdapter struct {
	C.ProxyAdapter
	name string
	addr string
}

func (a *leafAdapter) Name() string { return a.name }
func (a *leafAdapter) Addr() string { return a.addr }

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
	waitFor(t, func() bool { return group.forced.Load() == 1 }, "форс-чек группы")

	if got := provider.checked.Load(); got != 0 {
		t.Fatalf("провайдер проверен штатным путём %d раз, ожидался только форс-чек", got)
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

func (d *fakeDialer) setReachable(reachable bool) {
	d.mu.Lock()
	d.reachable = reachable
	d.mu.Unlock()
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
		map[string]C.Proxy{
			"node": &fakeProxy{adapter: &leafAdapter{name: "node", addr: "example.com:443"}, typ: C.Vless, addr: "example.com:443"},
		},
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
		map[string]C.Proxy{
			"node": &fakeProxy{adapter: &leafAdapter{name: "node", addr: "example.com:443"}, typ: C.Vless, addr: "example.com:443"},
		},
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

// Повторная смена сети отменяет недоигранную реакцию на предыдущую.
func TestReadinessGateCancelledByNewerGeneration(t *testing.T) {
	provider := &fakeProvider{name: "provider"}
	setTunnelState(t,
		map[string]C.Proxy{
			"node": &fakeProxy{adapter: &leafAdapter{name: "node", addr: "example.com:443"}, typ: C.Vless, addr: "example.com:443"},
		},
		map[string]P.ProxyProvider{"provider": provider},
	)

	dial := &fakeDialer{reachable: false}
	checker := gateChecker(dial)

	// Два сигнала подряд: второй схлопывается дебаунсом, но своё поколение
	// заводит — и гейт первого обязан замолчать.
	checker.trigger()
	time.Sleep(checker.interval)
	checker.trigger()

	waitFor(t, func() bool { return provider.forced.Load() == 2 }, "залп гейта последнего поколения")
	time.Sleep(2 * checker.timeout)

	if got := provider.forced.Load(); got != 2 {
		t.Fatalf("залпов: %d, ожидалось 2 (немедленный и один гейтовый) — гейт отменённого поколения выстрелил", got)
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
			"node":    &fakeProxy{adapter: &leafAdapter{name: "node", addr: "example.com:443"}, typ: C.Vless, addr: "example.com:443"},
			"nodedup": &fakeProxy{adapter: &leafAdapter{name: "nodedup", addr: "example.com:443"}, typ: C.Vless, addr: "example.com:443"},
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
