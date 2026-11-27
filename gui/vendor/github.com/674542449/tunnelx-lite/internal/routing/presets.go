package routing

import (
	"fmt"
	"strings"
)

// DirectPreset 描述一组可自由开关的内置直连规则包（在绕过大陆和全局模式下均生效）。
type DirectPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

var builtinDirectPresets = []DirectPreset{
	{
		ID:          "netease",
		Name:        "网易系直连",
		Description: "网易云音乐、网易游戏、国服战网、邮箱、有道、网易云信、LOFTER 及 CDN 资源",
		Domains: []string{
			"163.com",
			"126.com",
			"126.net",
			"127.net",
			"166.net",
			"16163.com",
			"163yun.com",
			"yeah.net",
			"netease.com",
			"netease.cn",
			"netease.im",
			"neteasegames.com",
			"nease.net",
			"easebar.com",
			"youdao.com",
			"ydstatic.com",
			"lofter.com",
			"lf127.net",
			"icourse163.org",
			"qiyukf.com",
			"battlenet.com.cn",
			"blizzard.cn",
			"blzstatic.cn",
		},
	},
	{
		ID:          "tencent",
		Name:        "腾讯系直连",
		Description: "微信/WeChat、QQ、QQ 音乐、腾讯视频、腾讯会议、WeGame/腾讯游戏、微信支付及腾讯云 CDN",
		Domains: []string{
			"qq.com",
			"qqmail.com",
			"weixin.com",
			"wechat.com",
			"weixinbridge.com",
			"servicewechat.com",
			"wechatpay.cn",
			"tenpay.com",
			"gtimg.com",
			"gtimg.cn",
			"qpic.cn",
			"qlogo.cn",
			"idqqimg.com",
			"url.cn",
			"myapp.com",
			"sogou.com",
			"sogoucdn.com",
			"tencent.com",
			"tencent.cn",
			"tencent.net",
			"tencentmusic.com",
			"yqq.com",
			"weiyun.com",
			"foxmail.com",
			"qzone.com",
			"wegame.com",
			"wegame.com.cn",
			"qqgame.com",
			"igamecj.com",
			"gcloudcs.com",
			"gcloudsdk.com",
			"gclouddn.com",
			"imtmp.net",
			"qcloudgme.com",
			"qcloud.com",
			"myqcloud.com",
			"qcloudcdn.com",
			"qcloudimg.com",
			"qcloudtcic.com",
			"qcloudclass.com",
			"tencent-cloud.net",
			"tencent-cloud.com",
			"tencentcloudapi.com",
			"tencentcs.com",
			"tencentcos.cn",
			"tencentcos.com",
			"tencentcos.com.cn",
			"cdntips.com",
			"cdntips.net",
			"dnsv1.com",
			"dnspod.cn",
			"dnspod.com",
			"dnspod.net",
			"smtcdns.com",
			"smtcdns.net",
			"tcdnlive.com",
			"tcdnhw.com",
			"tcdnos.com",
		},
	},
}

// BuiltinDirectPresets 返回所有可供用户勾选启用的内置直连规则包副本。
func BuiltinDirectPresets() []DirectPreset {
	out := make([]DirectPreset, len(builtinDirectPresets))
	for i, p := range builtinDirectPresets {
		p.Domains = append([]string(nil), p.Domains...)
		out[i] = p
	}
	return out
}

// NormalizeDirectPresets 校验、去重并按固定顺序规范化内置规则包 ID 列表。
func NormalizeDirectPresets(ids []string) ([]string, error) {
	want := make(map[string]bool, len(ids))
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		found := false
		for _, p := range builtinDirectPresets {
			if p.ID == id {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("未知的内置直连规则包：%s", raw)
		}
		want[id] = true
	}
	if len(want) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(want))
	for _, p := range builtinDirectPresets {
		if want[p.ID] {
			out = append(out, p.ID)
		}
	}
	return out, nil
}

// BuildDirectPresetsRules 将已启用的内置规则包编译为后缀匹配 *Rules。
func BuildDirectPresetsRules(ids []string) (*Rules, error) {
	norm, err := NormalizeDirectPresets(ids)
	if err != nil {
		return nil, err
	}
	if len(norm) == 0 {
		return nil, nil
	}
	enabled := make(map[string]bool, len(norm))
	for _, id := range norm {
		enabled[id] = true
	}
	var sb strings.Builder
	for _, p := range builtinDirectPresets {
		if !enabled[p.ID] {
			continue
		}
		for _, d := range p.Domains {
			sb.WriteString("domain:")
			sb.WriteString(d)
			sb.WriteByte('\n')
		}
	}
	return Parse([]byte(sb.String()), nil)
}
