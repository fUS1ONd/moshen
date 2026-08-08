package provider

import (
	"context"
	"sync/atomic"
	"testing"

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
}

func (p *countingProxy) Name() string { return p.name }

func (p *countingProxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	p.tests.Add(1)
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
