# Защита autonovad.ua от парсинга через Cloudflare

## Контекст

| Параметр | Значение |
|----------|----------|
| **Домен (фронт)** | `autonovad.ua` (React SPA) |
| **Домен (API)** | `catalogue-api.autonovad.ua` |
| **CF Plan** | Pro |
| **Трафик** | ~2.14M req/day (фронт), ~955k req/day (API) |
| **Origin** | EKS → nginx-ingress → ELB (`public-shared-nginx-prod-*.elb.eu-central-1.amazonaws.com`) |
| **Оба домена** | Proxied (оранжевое облако) |
| **API auth** | Нет — открытый GET, без токенов/ключей |
| **CORS** | `Access-Control-Allow-Origin: *` |
| **SSL Mode** | Full (Strict) |
| **Turnstile** | Пока не внедряем |
| **ELB** | Shared (несколько сервисов), whitelist на уровне Ingress |
| **Кэширование API** | Нельзя — offers обновляются в реалтайме |

### Лимиты CF Pro план

| Ресурс | Pro |
|--------|-----|
| Custom Rules (WAF) | 20 (использовано 7) |
| Rate Limiting Rules | 2 |
| Super Bot Fight Mode | Да |
| Bot Score в выражениях | Нет (только Enterprise + Bot Management) |
| Cache Rules | 25 |
| Transform Rules | 25 |

### API эндпоинты, которые нужно защитить

```
GET /api/products/{code}/external-offers
GET /api/products/{code}/offers
GET /api/products/{code}/extended-offers
```

Коды товаров — сотни тысяч. Реальный пользователь — до 50 товаров за сессию.

---

## Общий план защиты (порядок выполнения)

```
Шаг 1: Закрыть прямой доступ к origin (обход CF) — на уровне Ingress
Шаг 2: Ограничить CORS
Шаг 3: Super Bot Fight Mode
Шаг 4: WAF Custom Rules (challenge + block)
Шаг 5: Rate Limiting
Шаг 6: Мониторинг и тюнинг
```

> **Кэширование API (Шаг 6 в предыдущей версии) исключено** — offers обновляются в реалтайме, кэш невозможен. Это делает остальные слои защиты критически важными, т.к. каждый пропущенный бот-запрос = нагрузка на origin.

---

## Шаг 1: Закрыть прямой доступ к origin

**Проблема:** ELB `public-shared-nginx-prod-*.elb.eu-central-1.amazonaws.com` доступен напрямую. Любой может обращаться к origin в обход Cloudflare, и все правила CF становятся бесполезными.

**Ограничение:** ELB shared — через него ходит трафик других сервисов. Закрывать на уровне Security Group нельзя. Поэтому защита реализуется на уровне Ingress (nginx-ingress-controller).

**Два подхода — использовать оба:**

### 1.1. Whitelist Cloudflare IP на уровне Ingress

nginx-ingress-controller поддерживает annotation `whitelist-source-range`, которая ограничивает доступ к конкретному Ingress-ресурсу по IP. Однако при таком количестве CIDR'ов CF удобнее использовать server-snippet или ConfigMap подход.

**Вариант A: annotation (простой, но длинный)**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: catalogue-api
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: >-
      173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,
      141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,
      197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,
      104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
spec:
  rules:
    - host: catalogue-api.autonovad.ua
      # ...
```

> **Минус:** Annotation — строка, при изменении CF IP нужно перекатывать Ingress.

**Вариант B: server-snippet + переменная (гибкий)**

Создать ConfigMap с CF IP ranges и подключить через server-snippet:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudflare-ip-ranges
  namespace: ingress-nginx  # или где стоит ingress controller
data:
  cloudflare-ips.conf: |
    # Cloudflare IPv4 — актуальный список: https://www.cloudflare.com/ips-v4
    allow 173.245.48.0/20;
    allow 103.21.244.0/22;
    allow 103.22.200.0/22;
    allow 103.31.4.0/22;
    allow 141.101.64.0/18;
    allow 108.162.192.0/18;
    allow 190.93.240.0/20;
    allow 188.114.96.0/20;
    allow 197.234.240.0/22;
    allow 198.41.128.0/17;
    allow 162.158.0.0/15;
    allow 104.16.0.0/13;
    allow 104.24.0.0/14;
    allow 172.64.0.0/13;
    allow 131.0.72.0/22;
    # Cloudflare IPv6 — актуальный список: https://www.cloudflare.com/ips-v6
    allow 2400:cb00::/32;
    allow 2606:4700::/32;
    allow 2803:f800::/32;
    allow 2405:b500::/32;
    allow 2405:8100::/32;
    allow 2a06:98c0::/29;
    allow 2c0f:f248::/32;
    deny all;
```

Затем в Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: catalogue-api
  annotations:
    nginx.ingress.kubernetes.io/server-snippet: |
      include /etc/nginx/cloudflare-ips.conf;
spec:
  rules:
    - host: catalogue-api.autonovad.ua
      # ...
```

И примонтировать ConfigMap в nginx-ingress-controller deployment:

```yaml
# В Helm values для ingress-nginx (или в deployment)
controller:
  extraVolumeMounts:
    - name: cloudflare-ips
      mountPath: /etc/nginx/cloudflare-ips.conf
      subPath: cloudflare-ips.conf
      readOnly: true
  extraVolumes:
    - name: cloudflare-ips
      configMap:
        name: cloudflare-ip-ranges
```

> **Важно:** CF периодически добавляет IP. Настрой CronJob или CI/CD pipeline для автоматического обновления ConfigMap. Актуальный список: https://www.cloudflare.com/ips/

> **Важно:** Убедись что `use-forwarded-headers` или `use-proxy-protocol` настроен в ingress-controller, чтобы nginx видел реальный source IP (CF edge IP), а не внутренний IP ELB.

**Скрипт для автообновления ConfigMap:**

```bash
#!/bin/bash
# update-cf-ips.sh — запускать по крону или в CI
NAMESPACE="ingress-nginx"
CM_NAME="cloudflare-ip-ranges"

IPV4=$(curl -s https://www.cloudflare.com/ips-v4)
IPV6=$(curl -s https://www.cloudflare.com/ips-v6)

CONF=""
for ip in $IPV4; do CONF+="    allow ${ip};\n"; done
for ip in $IPV6; do CONF+="    allow ${ip};\n"; done
CONF+="    deny all;"

kubectl create configmap $CM_NAME \
  --from-literal=cloudflare-ips.conf="$(echo -e "$CONF")" \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Перезагрузить ingress-controller чтобы подхватил изменения
kubectl rollout restart deployment ingress-nginx-controller -n $NAMESPACE
```

### 1.2. Authenticated Origin Pulls (mTLS)

Дополнительный слой — CF при каждом запросе к origin предъявляет клиентский сертификат. nginx проверяет, что сертификат валидный. Даже если кто-то узнает IP и подделает source IP — без клиентского сертификата запрос не пройдёт.

**В Cloudflare Dashboard:**

1. `SSL/TLS` → `Origin Server` → `Authenticated Origin Pulls` → **Включить**

**На nginx ingress (для catalogue-api.autonovad.ua):**

```bash
# 1. Скачать CF origin pull CA
curl -o cloudflare-origin-pull-ca.pem \
  https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem

# 2. Создать Secret
kubectl create secret generic cloudflare-origin-pull-ca \
  --from-file=ca.crt=cloudflare-origin-pull-ca.pem \
  -n <namespace-где-ingress>
```

**Ingress с mTLS annotations:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: catalogue-api
  annotations:
    # IP whitelist (Вариант A)
    nginx.ingress.kubernetes.io/whitelist-source-range: >-
      173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,
      141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,
      197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,
      104.24.0.0/14,172.64.0.0/13,131.0.72.0/22
    # mTLS — Authenticated Origin Pulls
    nginx.ingress.kubernetes.io/auth-tls-secret: "<namespace>/cloudflare-origin-pull-ca"
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
    nginx.ingress.kubernetes.io/auth-tls-verify-depth: "1"
spec:
  rules:
    - host: catalogue-api.autonovad.ua
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: catalogue-api-svc
                port:
                  number: 80
```

> **SSL mode Full (Strict) уже настроен** — это ОК, Authenticated Origin Pulls работает.

> **Применить к обоим Ingress'ам** — и для `catalogue-api.autonovad.ua`, и для `autonovad.ua`, чтобы закрыть обход CF на обоих доменах.

**Проверка:**

```bash
# Прямой запрос к ELB (должен вернуть 403 или 400 "No required SSL certificate")
curl -v https://public-shared-nginx-prod-*.elb.eu-central-1.amazonaws.com \
  -H "Host: catalogue-api.autonovad.ua"
# Ожидаемый результат: 403 Forbidden или SSL handshake error

# Запрос через CF (должен работать)
curl -v https://catalogue-api.autonovad.ua/api/products/02219_541/offers
# Ожидаемый результат: 200 OK с JSON
```

---

## Шаг 2: Ограничить CORS

**Проблема:** `Access-Control-Allow-Origin: *` позволяет любому сайту делать запросы к API из браузера. Парсеры могут создать свою HTML-страницу с JS, который массово тянет данные с API.

**Действие:** Изменить CORS на бэкенде:

```yaml
# Было
CORS_ALLOW_ORIGIN: "*"

# Стало
CORS_ALLOW_ORIGIN: "https://autonovad.ua"
```

Или если есть другие легитимные домены (staging и т.д.):

```yaml
CORS_ALLOW_ORIGIN: "https://autonovad.ua,https://staging.autonovad.ua"
```

> **Важно:** Это НЕ защита от серверных парсеров (curl, Python requests и т.д.) — они просто игнорируют CORS. Но это закрывает браузерный вектор.

---

## Шаг 3: Super Bot Fight Mode

**Что это:** Встроенная в CF Pro функция, которая использует машинное обучение CF для классификации трафика на "definitely automated", "likely automated", "likely human".

**Настройка:**

1. `Security` → `Bots` (или `Security` → `Settings`, секция Bot traffic)
2. Настроить **Super Bot Fight Mode**:

| Категория | Действие |
|-----------|----------|
| **Definitely automated** | **Block** |
| **Likely automated** | **Managed Challenge** |
| **Verified bots** (Googlebot и т.д.) | **Allow** |

3. **Static resource protection** — **Выключить** (не нужно челленджить CSS/JS/images)
4. **JavaScript Detections** — **Включить** (добавляет invisible JS challenge на страницы для fingerprinting)

> **Важно:** Super Bot Fight Mode может челленджить запросы к API. Поскольку API вызывается из React SPA (XHR/fetch из браузера), а пользователь уже прошёл challenge на основном сайте — это обычно не проблема. Но нужно протестировать.

> **Если возникнут проблемы с API-запросами из SPA**, создать Custom Rule (Skip) — см. Шаг 4.

---

## Шаг 4: WAF Custom Rules

Сейчас использовано 7 из 20 правил. Ниже — правила для защиты от парсинга. Порядок важен (правила выполняются сверху вниз).

### Правило 8: Skip SBFM для легитимных ботов (поисковые боты на фронте)

Гуглбот и другие поисковые боты должны индексировать фронт (`autonovad.ua`), но **не** API.

```
Name: Allow verified bots on frontend
Expression:
  (cf.bot_management.verified_bot and http.host eq "autonovad.ua")

Action: Skip
  → Skip: Super Bot Fight Mode Rules
```

### Правило 9: Block direct API access без Referer

Легитимные запросы от React SPA всегда имеют `Referer: https://autonovad.ua/...`. Прямые запросы от парсеров — обычно нет.

```
Name: Challenge API without valid referer
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and not http.referer contains "autonovad.ua"
   and not cf.bot_management.verified_bot)

Action: Managed Challenge
```

> **Примечание:** Referer легко подделать, поэтому это лишь один из слоёв защиты, а не единственная мера. Action = Managed Challenge, а не Block — чтобы легитимные edge-case'ы (старые браузеры, расширения) могли пройти.

### Правило 10: Challenge подозрительных User-Agent на API

Блокировать известные scraping-библиотеки и пустые UA.

```
Name: Block suspicious UA on API
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and (
     http.user_agent eq ""
     or http.user_agent contains "python"
     or http.user_agent contains "requests"
     or http.user_agent contains "scrapy"
     or http.user_agent contains "wget"
     or http.user_agent contains "curl"
     or http.user_agent contains "httpx"
     or http.user_agent contains "aiohttp"
     or http.user_agent contains "Go-http-client"
     or http.user_agent contains "Java/"
     or http.user_agent contains "libwww"
     or http.user_agent contains "Mechanize"
     or http.user_agent contains "Selenium"
     or http.user_agent contains "PhantomJS"
     or http.user_agent contains "Headless"
     or http.user_agent contains "node-fetch"
     or http.user_agent contains "axios"
   ))

Action: Block
```

> **Примечание:** Продвинутые парсеры подделывают UA, но это отсеет ленивых.

### Правило 11: Challenge API по Threat Score

CF присваивает каждому IP threat score (0 = чистый, 100 = максимальная угроза). На Pro доступен `cf.threat_score`.

```
Name: Challenge high threat score on API
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and cf.threat_score gt 10)

Action: Managed Challenge
```

### Правило 12: Block non-browser HTTP methods на API

API используется только через GET из SPA. Блокировать всё остальное.

```
Name: Block non-GET on API catalogue
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and http.request.uri.path contains "/api/products/"
   and not http.request.method eq "GET")

Action: Block
```

### Правило 13: Challenge по стране (опционально)

Если бизнес ориентирован на Украину и парсинг идёт из конкретных регионов.

```
Name: Challenge non-UA traffic on API
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and not ip.geoip.country eq "UA"
   and not cf.bot_management.verified_bot)

Action: Managed Challenge
```

> **Используй осторожно.** Если есть клиенты за рубежом — не включай, или добавь исключения. Посмотри в CF Analytics географию запросов перед включением.

---

## Шаг 5: Rate Limiting

Pro план даёт **2 правила** rate limiting. Используем оба.

### Rate Limit Rule 1: Общий лимит на API по IP

Цель: ограничить количество запросов к API с одного IP.

Расчёт: реальный пользователь смотрит до 50 товаров за сессию. Каждый товар = 3 запроса (external-offers, offers, extended-offers). Это ~150 запросов за сессию. Сессия может длиться 10-30 минут. Берём запас: **200 запросов за 1 минуту** — реальный пользователь не превысит (это ~3.3 req/sec).

```
Name: API rate limit per IP
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and http.request.uri.path contains "/api/products/")

Characteristics: IP
Period: 1 minute (60 seconds)
Requests per period: 200
Mitigation timeout: Managed Challenge (при превышении)

Action: Managed Challenge
```

> **Почему Managed Challenge, а не Block:** на Pro при challenge-действии CF использует request throttling — пользователь получает challenge, проходит его, и счётчик сбрасывается. Это мягче чем блокировка на фиксированное время.

> **Тюнинг:** Начни с 200/min. Через неделю посмотри в Security Events — если много легитимных пользователей попадают, увеличь до 300. Если мало ботов попадает, уменьши до 100.

### Rate Limit Rule 2: Агрессивный лимит на burst

Цель: поймать быстрый перебор (бот, который дёргает API со скоростью 10+ req/sec).

```
Name: API burst rate limit
Expression:
  (http.host eq "catalogue-api.autonovad.ua"
   and http.request.uri.path contains "/api/products/")

Characteristics: IP
Period: 10 seconds
Requests per period: 30
Mitigation timeout: Block (60 seconds)

Action: Block
Duration: 60 seconds
```

> **Логика:** 30 запросов за 10 секунд = 3 req/sec. Нормальный пользователь не генерирует такой burst. При превышении — блок на минуту.

---

## Шаг 6: Мониторинг и тюнинг

### 6.1. Security Events

`Security` → `Events` — основной инструмент.

**Что мониторить:**

- **Фильтр по Service = "Rate limiting"** — кто попадает в rate limit. Если видишь UA реальных браузеров — лимит слишком строгий.
- **Фильтр по Service = "Super Bot Fight Mode"** — кто челленджится/блокируется ботфайтом.
- **Фильтр по Action = "Managed Challenge" + Result = "Pass"** — сколько реальных людей проходят challenge (норма).
- **Фильтр по Action = "Block"** — что блокируется, не попадают ли легитимные запросы.

### 6.2. Analytics

`Analytics & Logs` → `Traffic`:

- Следи за общим количеством запросов — после включения защиты объём должен снизиться.
- Сравнивай трафик к `catalogue-api.autonovad.ua` до и после каждого этапа.

### 6.3. Origin-side мониторинг

На стороне nginx/бэкенда:

- Логировать `CF-Connecting-IP` заголовок (реальный IP клиента, а не CF edge IP).
- Мониторить RPS к origin — после включения rate limiting должен упасть.
- Если видишь запросы без `CF-Connecting-IP` — кто-то обходит CF напрямую (значит Шаг 1 не полностью выполнен).

---

## Порядок внедрения (рекомендация)

Не включай всё сразу. Поэтапно, с проверкой на каждом шаге:

### Неделя 1: Основа
1. **Шаг 1** — закрыть origin (Ingress whitelist + Authenticated Origin Pulls)
2. **Шаг 2** — ограничить CORS
3. **Шаг 3** — включить Super Bot Fight Mode
4. Мониторить Security Events 2-3 дня

### Неделя 2: WAF Rules
5. **Шаг 4** — включать правила по одному:
   - Сначала правило по UA (Rule 10) — оно самое безопасное
   - Затем Referer check (Rule 9)
   - Затем Threat Score (Rule 11)
   - Гео-ограничение (Rule 13) — только если подтвердишь что нет зарубежных клиентов
6. Мониторить Security Events после каждого правила

### Неделя 3: Rate Limiting
7. **Шаг 5** — сначала burst rate limit (Rule 2), затем общий (Rule 1)
8. Мониторить неделю

### Неделя 4: Тюнинг
9. Проанализировать данные, скорректировать пороги rate limit
10. Добавить/убрать UA в блок-лист

---

## Дополнительные рекомендации (вне рамок CF)

### Фронтенд (React)

Если в будущем решите внедрить Turnstile — это самый эффективный вариант:

1. Добавить Turnstile widget на страницу поиска (invisible mode)
2. При каждом поисковом запросе отправлять Turnstile token вместе с API-запросом
3. Бэкенд валидирует token через CF API перед отдачей данных
4. Без валидного token — 403

Это закроет парсинг почти полностью, т.к. Turnstile требует реальный браузер с JS execution.

### Бэкенд

- **Honeypot эндпоинты:** Создать фейковые URL типа `/api/products/TRAP-000/offers` и вставить их в HTML (CSS hidden). Боты пойдут по ним → логировать/банить IP.
- **Рандомизация структуры:** Менять формат кода товара в URL (если возможно) — усложнит перебор.
- **Response fingerprinting:** Добавлять в JSON-ответ уникальный невидимый идентификатор (UUID в поле, которое фронт игнорирует). Если увидишь свои данные на чужом сайте — сможешь отследить через какой запрос утекли.

---

## Чеклист после внедрения

- [ ] Origin недоступен напрямую (curl к ELB с Host header возвращает 403/SSL error)
- [ ] Authenticated Origin Pulls включен и работает
- [ ] Ingress whitelist-source-range содержит актуальные CF IP
- [ ] CORS ограничен `https://autonovad.ua`
- [ ] Super Bot Fight Mode: Definitely Automated = Block, Likely Automated = Challenge
- [ ] WAF Custom Rules активны (проверить Security Events)
- [ ] Rate Limiting активен (проверить Security Events)
- [ ] Фронт работает корректно (протестировать поиск, просмотр товаров)
- [ ] Googlebot индексирует фронт нормально (Google Search Console)
- [ ] Нет false positives в Security Events за неделю

---

## FAQ

**Q: Парсер использует headless Chrome — CF его пропустит?**
A: Super Bot Fight Mode детектирует часть headless-браузеров по JS fingerprinting. Но продвинутые (undetected-chromedriver, playwright со стелс-плагинами) могут пройти. Rate limiting и кэширование всё равно ограничат скорость парсинга. Для полной защиты нужен Turnstile или Enterprise Bot Management.

**Q: Что если rate limit слишком строгий и блокирует реальных пользователей?**
A: Начни с мягких лимитов (200/min, Managed Challenge). Мониторь Security Events. Если видишь реальные браузерные UA — увеличивай порог или переключи на Managed Challenge вместо Block.

**Q: Стоит ли перейти на Business план?**
A: Business даёт 100 Custom Rules (вместо 20) и 5 Rate Limiting Rules (вместо 2). Если текущих правил не хватает или нужны более гранулярные rate limits — имеет смысл. Также Business позволяет отдельные counting и mitigation expressions в rate limiting.

**Q: Как понять что защита работает?**
A: Сравни метрики до/после: RPS на origin, объём трафика в CF Analytics, количество заблокированных запросов в Security Events. Если origin RPS снизился, а трафик в CF остался — защита работает, CF берёт на себя нагрузку.
