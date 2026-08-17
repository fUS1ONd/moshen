package provider

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

// countingProxy — нода, считающая проверки живости. Встроенный C.Proxy оставлен
// nil намеренно: health-check дальше перечисленных методов не ходит, а вызов
// любого другого упадёт паникой и покажет, что тест разошёлся с реальностью.
type countingProxy struct {
	C.Proxy
	name  string
	tests atomic.Int32
	// block, если задан, держит пробу до закрытия канала: нужен, чтобы поймать
	// момент, когда проверка уже идёт, и посмотреть, что сделают конкуренты.
	block chan struct{}
}

func (p *countingProxy) Name() string { return p.name }

func (p *countingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
	if p.block != nil {
		<-p.block
	}
	return 0, nil
}

func (p *countingProxy) AliveForTestUrl(url string) bool       { return true }
func (p *countingProxy) LastDelayForTestUrl(url string) uint16 { return 0 }

// Смена сети приходит через доли секунды после штатной проверки, и та проверка
// сделана ещё через прежний путь. Форс-чек обязан сбросить окно дедупликации.
func TestForceHealthCheckBypassesDedupWindow(t *testing.T) {
	proxy := &countingProxy{name: "node"}
	// interval 0 — фоновый цикл проверок не запускается, в тесте всё вручную.
	hc := NewHealthCheck([]C.Proxy{proxy}, "http://health.invalid", 100, 0, false, nil)
	provider, err := NewCompatibleProvider("test", []C.Proxy{proxy}, hc)
	if err != nil {
		t.Fatalf("создание провайдера: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	provider.HealthCheck()
	if got := proxy.tests.Load(); got != 1 {
		t.Fatalf("после первой проверки проб: %d, ожидалась 1", got)
	}

	// Повтор в пределах окна дедупликации отдаёт закэшированный результат.
	provider.HealthCheck()
	if got := proxy.tests.Load(); got != 1 {
		t.Fatalf("штатная проверка в окне дедупликации дала %d проб, ожидался кэш", got)
	}

	provider.ForceHealthCheck()
	if got := proxy.tests.Load(); got != 2 {
		t.Fatalf("после форс-чека проб: %d, ожидалось 2", got)
	}
}

// Залп форс-чека приходит к одному провайдеру с нескольких сторон сразу: из
// общей карты провайдеров и от каждой группы с use:. Конкурентные форс-чеки
// обязаны присоединиться к уже идущей проверке, а не запускать каждый свою —
// иначе вместо ускорения выходит шторм проб по всем нодам подписки.
func TestForceHealthCheckJoinsInFlightCheck(t *testing.T) {
	release := make(chan struct{})
	proxy := &countingProxy{name: "node", block: release}
	hc := NewHealthCheck([]C.Proxy{proxy}, "http://health.invalid", 100, 0, false, nil)
	provider, err := NewCompatibleProvider("test", []C.Proxy{proxy}, hc)
	if err != nil {
		t.Fatalf("создание провайдера: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	const callers = 5
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			provider.ForceHealthCheck()
		}()
	}

	deadline := time.Now().Add(2 * time.Second)
	for proxy.tests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	// Даём отставшим форс-чекам дойти до singleDo и упереться в идущую пробу.
	time.Sleep(100 * time.Millisecond)

	if got := proxy.tests.Load(); got != 1 {
		t.Fatalf("%d конкурентных форс-чеков дали %d проб, ожидалась одна общая", callers, got)
	}

	close(release)
	wg.Wait()
}
