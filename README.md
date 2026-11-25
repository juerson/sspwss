# SSP (Simple Stealth Protocol) 

自研协议 cf workers 代理工具验证，包括服务端（worker/do）与 客户端（CLI核心+GUI）结合使用，缺一不可。

## 文件夹项目说明

### 1、服务端

- ssp-server：用于部署 CF 中，DO文件夹，只能部署 worker 端，可选里面的 pages 部署，调用 worker 端的 DO 从而使用 pages.dev 域名；Worker 文件夹，随意部署，Worker 端和 Pages 端。需要会 wrangler 命令和 CF 部署的门槛。

### 2、客户端

#### CLI 核心
- ssp-client-go：go语言编写的
- ssp-client-rs：rust语言编写的

#### GUI 界面
- ssp-client-gui-wails-v3：Go + Wails v3 技术栈
- ssp-client-gui-winfroms：C# Winfroms + net10.0 技术栈（vs2026）

选中哪个GUI客户端，其配置文件config.json都是可以共用的，复制到另一个也能使用（复制到主程序根目录就能读取配置文件，不用跑得到 "C:\Users\<你的用户名>\AppData\Roaming\SSP Workers\config.json"，跟后面介绍的 `byJoey/ech-wk`，项目里面介绍的配置文件保存在位置相差不大，文件夹名不同）

## 灵感来源

1、[byJoey/ech-wk](https://github.com/byJoey/ech-wk) （提供协议可以简单地 DIY 的）
2、[cfal/shoes](https://github.com/cfal/shoes)、[ibigbug/clash-rs](https://github.com/ibigbug/clash-rs) （提供 DNS 防泄漏帮助，解决 DNS 泄漏问题）