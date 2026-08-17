package intel

import (
	"fmt"
	"net"
	"sync"
)

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
}

// GeoIPLookup GeoIP 解析器
type GeoIPLookup struct {
	mu sync.RWMutex
}

// NewGeoIPLookup 创建 GeoIP 解析器
func NewGeoIPLookup() *GeoIPLookup {
	return &GeoIPLookup{}
}

// Lookup 查询 IP 的地理位置
func (g *GeoIPLookup) Lookup(ip string) (*GeoLocation, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	// 私有 IP 返回内网标记
	if parsedIP.IsPrivate() || parsedIP.IsLoopback() {
		return &GeoLocation{
			Country:     "Private",
			CountryCode: "PV",
			City:        "Internal",
		}, nil
	}

	// 实际实现中加载 MaxMind GeoLite2-City.mmdb 进行查询
	// 这里返回空结果，等待 mmdb 文件配置后启用
	return &GeoLocation{}, nil
}
