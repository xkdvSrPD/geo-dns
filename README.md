> AI糊的 质量不保证
> 本人Go学习中，本项目只用来练习，大佬不要对代码抱有任何希望

# 功能/配置
- 配置多个nameservers，可以配置doh或ip
- 配置多个nameserver-group，对nameservers进行分组
- 配置分流/结果选择规则nameserver-policy

比如配置CN的dns服务器223.5.5.5和119.29.29.29，配置HK的dns服务器为8.8.8.8、1.1.1.1
此时客户端查询`www.microsoft.com`域名，4个DNS服务器分别返回了`123.103.1.52（GEO:CN）、123.103.1.52（GEO:CN）、23.219.73.192（GEO:HK）、61.147.219.124（GEO:CN）`
经过nameserver-policy匹配之后，优先选择了123.103.1.52作为本次查询的结果返回


# 配置文件

```yaml
listen: "[::]:1053"
bootstrap-nameservers: 
  - 223.5.5.5
  - 119.29.29.29

nameservers:
  - name: cn1
    type: doh
    server: https://223.6.6.6/dns-query
  - name: cn2
    type: doh
    server: https://223.5.5.5/dns-query

  - name: hk1
    type: doh
    server: https://1.1.1.1/dns-query
  - name: hk2
    type: doh
    server: https://8.8.8.8/dns-query
    ecs: 154.3.33.0/24

nameserver-group:
  - name: CN
    nameservers: [cn1, cn2]

  - name: HK
    nameservers: [hk1, hk2, hk3]
    ecs: 154.3.33.0/24

nameserver-policy:
  - GEOIP:CN,CN
  - GEOIP:PRIVATE,CN
  - MATCH,HK

geox-url: https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip-only-cn-private.dat
```

# 本地运行

- clone项目
- 创建config.yaml
- 运行