package outboundgroup

import (
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

const fallbackTestUrl = "http://fallback.invalid"

// stubProxy — участник группы с переключаемой живостью. Встроенный C.Proxy
// оставлен nil намеренно: выбор участника дальше перечисленных методов не
// ходит, а вызов любого другого упадёт паникой и покажет, что тест разошёлся
// с реальностью.
type stubProxy struct {
	C.Proxy
	name  string
	alive atomic.Bool
}

func newStubProxy(name string, alive bool) *stubProxy {
	p := &stubProxy{name: name}
	p.alive.Store(alive)
	return p
}

func (p *stubProxy) Name() string                    { return p.name }
func (p *stubProxy) Type() C.AdapterType             { return C.Vless }
func (p *stubProxy) AliveForTestUrl(url string) bool { return p.alive.Load() }

// newTestFallback собирает группу поверх обычного compatible-провайдера — так
// же, как её собирает разбор конфига.
func newTestFallback(t *testing.T, proxies ...C.Proxy) *Fallback {
	t.Helper()

	// interval 0 — фоновых проверок нет, живостью в тесте управляем сами.
	hc := provider.NewHealthCheck(proxies, fallbackTestUrl, 0, 0, true, nil)
	pd, err := provider.NewCompatibleProvider(provider.ReservedName, proxies, hc)
	if err != nil {
		t.Fatalf("создание провайдера: %v", err)
	}
	t.Cleanup(func() { _ = pd.Close() })

	group, err := NewFallback(
		GroupCommonOption{Name: "fallback", URL: fallbackTestUrl},
		FallbackOption{},
		proxies[0],
		[]P.ProxyProvider{pd},
	)
	if err != nil {
		t.Fatalf("создание группы: %v", err)
	}
	return group
}

// Пока живые есть, группа работает как раньше: первый живой по списку.
func TestFallbackPicksFirstAliveProxy(t *testing.T) {
	first := newStubProxy("first", false)
	second := newStubProxy("second", true)
	third := newStubProxy("third", true)
	group := newTestFallback(t, first, second, third)

	if got := group.Now(); got != "second" {
		t.Fatalf("выбран %q, ожидался первый живой по списку", got)
	}
}

// Все умерли — группа держится за последнего работавшего, а не откатывается на
// первого по списку.
func TestFallbackStaysOnLastAliveWhenAllDead(t *testing.T) {
	first := newStubProxy("first", false)
	second := newStubProxy("second", true)
	group := newTestFallback(t, first, second)

	if got := group.Now(); got != "second" {
		t.Fatalf("выбран %q, ожидался second", got)
	}

	second.alive.Store(false)

	if got := group.Now(); got != "second" {
		t.Fatalf("при всех мёртвых выбран %q, ожидался последний работавший second", got)
	}
}

// Живых не было вовсе — прежнее поведение, первый по списку: держаться не за
// что, а выбрать кого-то надо.
func TestFallbackFallsBackToFirstWhenNothingWasAlive(t *testing.T) {
	first := newStubProxy("first", false)
	second := newStubProxy("second", false)
	group := newTestFallback(t, first, second)

	if got := group.Now(); got != "first" {
		t.Fatalf("выбран %q, ожидался первый по списку", got)
	}
}

// Кто-то ожил — возвращается штатный выбор по приоритету, липкость не
// «залипает» навсегда.
func TestFallbackReturnsToPriorityChoiceAfterRecovery(t *testing.T) {
	first := newStubProxy("first", false)
	second := newStubProxy("second", true)
	group := newTestFallback(t, first, second)

	if got := group.Now(); got != "second" {
		t.Fatalf("выбран %q, ожидался second", got)
	}

	second.alive.Store(false)
	if got := group.Now(); got != "second" {
		t.Fatalf("при всех мёртвых выбран %q, ожидался second", got)
	}

	first.alive.Store(true)
	if got := group.Now(); got != "first" {
		t.Fatalf("после оживления выбран %q, ожидался приоритетный first", got)
	}
}
