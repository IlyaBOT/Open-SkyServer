# Open-SkyServer

Свой сервер для классического Skype. Сейчас работаем с клиентом **Skype 4.2.0.187 для Windows**: разбираем протокол, восстанавливаем серверную часть и проверяем её на настоящем клиенте.

Основная работа идёт над сервером на Go для Linux. Версия на C# остаётся в репозитории как референс. Клиент подключается к нашей сети после замены адресов и публичных ключей. Одного изменения `hosts` для этого недостаточно.

## Что уже работает

| Возможность | Состояние |
| --- | --- |
| Вход и регистрация из Skype | Проверены на Go-сервере, включая вход из нового локального профиля. |
| Поиск пользователей | Работает через серверный справочник. |
| Загрузка списка контактов | Проверена для существующих контактных документов. Полный цикл запроса, принятия и отклонения ещё не закончен. |
| Текстовые сообщения | Два клиента на одном ПК обменивались сообщениями напрямую по P2P. Доставка через разные NAT и серверная очередь пока не подтверждены. |
| Статусы | Обновляются между контактами, но есть задержки, особенно при переходе в "Невидимый" и "Не в сети". |
| Звонки | Наблюдали вызов и принятие звонка. Работу звука пока не подтвердили, полноценного media relay нет. |
| Профиль и аватар | Часть полей восстанавливается с сервера. Полная синхронизация профиля и загрузка аватара в новый профиль пока не работают. |
| Счётчик онлайна | Пока не восстановлен. Он должен учитывать Online, Away и DND, исключая Invisible и Offline. |

Главная текущая задача - связь между клиентами в разных сетях. Успешный локальный чат ещё не означает, что готова работа через Интернет. Подробности и план следующего теста есть в [WAN_CHECKPOINT.md](server/go/WAN_CHECKPOINT.md).

## Подключить клиент

Нужны Windows, Windows PowerShell 5.1, Python 3 и оригинальный `Skype.exe` версии 4.2.0.187. При первом запуске патчера понадобится Интернет для загрузки двух Python-модулей. Они устанавливаются в папку патчера.

1. Получите ZIP-патчер у владельца сервера. Он должен быть собран для адреса и ключей этого сервера. В исходниках готового `community.patch.json` нет.
2. Распакуйте архив в обычную папку, доступную для записи.
3. Запустите `Patch-Skype.cmd` и выберите оригинальный `Skype.exe`. Можно просто перетащить EXE на этот CMD-файл.
4. Дождитесь окончания обработки и откройте ярлык **Skype 4.2.0.187 Patched** на рабочем столе.

Патчер создаёт отдельную папку с клиентом, резервной копией `Skype.exe.bak` и новым профилем. Выбранный исходный файл он не меняет. Ярлык запускает клиент через помощник, который настраивает сервер поиска и отслеживает появление настроек аккаунта после первого входа. Файлы настроек обновляются автоматически; подхватывает ли Skype эти изменения уже в первом сеансе, ещё нужно проверить.

Поддерживается только оригинальный EXE с этим SHA-256:

```text
A2E175CE7C9888C125E2B3D4C2343229832BA0D0CD8A8A1CE120CE92624E856C
```

Другие сборки 4.2, а также Skype 4.4 и 5.5 этим патчером не поддерживаются. Готовые пакеты не публикуются автоматически вместе с исходниками. Как собрать свой пакет, описано ниже и в [документации патчера](patcher/README.md).

## Поднять сервер

Ниже пример для Debian или Ubuntu на x86-64. Нужны Go 1.22 или новее, GCC с поддержкой 32-битной сборки и SQLite CLI. Проверьте `go version`: в старых дистрибутивах пакет Go может оказаться слишком старым.

```sh
sudo apt update
sudo apt install -y golang-go sqlite3 build-essential gcc-multilib libc6-dev-i386 file

git clone https://github.com/IlyaBOT/Open-SkyServer.git
cd Open-SkyServer/server/go
sh ./build-linux.sh
```

Сборка создаёт два файла: `bin/openskyserver` и `bin/skype_blob_worker`. Второй - отдельный 32-битный декодер списков протокола. Для работы клиента нужны оба.

### Ключи и база

Серверу нужны ключи той же сети, под которую собран клиентский патч. Для новой сети сначала создайте их на Windows по инструкции "Подготовить патчер" ниже. Если сервер уже существует, используйте его ключи.

```sh
sudo install -d -m 700 /etc/openskyserver/keys /var/lib/openskyserver
```

Перенесите в `/etc/openskyserver/keys` четыре файла: `login.private.xml`, `login.public.xml`, `credentials.private.xml`, `credentials.public.xml`. Закройте доступ к приватным файлам для остальных пользователей. Ключ `client-integrity` нужен на машине сборки патчера, переносить его на сервер не требуется.

Проверьте ключи и создайте базу:

```sh
sudo ./bin/openskyserver --check-keys --keys-dir /etc/openskyserver/keys
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --init-db
```

### Два тестовых аккаунта

Для быстрой проверки контактов создайте две учётки и сразу добавьте их друг другу. Команды выполняются из `server/go` и используют ту же базу, что и сервер:

```sh
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-account "admindev@test.lol" "Admin" "AdminDev"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --set-email "admindev@test.lol" "admindev@test.lol"

sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-account "second@test.lol" "Test Second Account" "SecondTest"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --set-email "second@test.lol" "second@test.lol"

sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-contact "admindev@test.lol" "second@test.lol"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --add-contact "second@test.lol" "admindev@test.lol"
```

| Логин | Пароль для теста |
| --- | --- |
| admindev@test.lol | AdminDev |
| second@test.lol | SecondTest |

Это публичные тестовые пароли, не используйте их для обычных аккаунтов. Повторный `--add-account` меняет пароль и имя существующей учётки. Взаимное добавление через базу удобно для проверки общения, но отдельно нужно проверять и штатный запрос в контакты из клиента.

После теста учётки можно удалить:

```sh
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --remove-account "admindev@test.lol"
sudo ./bin/openskyserver --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 --remove-account "second@test.lol"
```

Также можно зарегистрироваться из Skype. У созданных таким способом аккаунтов нет пароля в формате HTTP API: вход в клиент работает, а вход по обычному паролю через API для них не поддерживается.

### Запуск для тестов через Интернет

Наш тестовый сервер имеет внешний адрес `176.101.124.66` и адрес в LAN `192.168.1.170`. Для своей установки замените внешний IP в команде и пересоберите клиентский патч под него.

Создайте `/etc/openskyserver/allowlist.txt` и запишите туда внешние IP тестеров, по одному на строку. Поддерживаются IPv4, подсети CIDR и комментарии с `#`. Пустой файл запрещает все подключения. После изменения списка нужно перезапустить сервер.

Из папки `server/go`:

```sh
sudo ./bin/openskyserver \
  --mode global --host 0.0.0.0 --advertise-ip 176.101.124.66 \
  --real-skype-probe \
  --closed --allowlist /etc/openskyserver/allowlist.txt \
  --keys-dir /etc/openskyserver/keys \
  --db /var/lib/openskyserver/skyserver.db --sqlite /usr/bin/sqlite3 \
  --blob-worker ./bin/skype_blob_worker
```

За роутером направьте порты на машину сервера. Внешний и внутренний номера портов должны совпадать:

| Протокол | Порты |
| --- | --- |
| TCP | 80, 443, 12350, 12351, 13392, 33033, 40001-40036 |
| UDP | 12350, 12351, 13392, 33033, 40001-40036 |

HTTP API слушает `127.0.0.1:33034`. Его не нужно открывать или пробрасывать наружу. Порты 80 и 443 здесь используются старым протоколом Skype, это не веб-сайт.

Если клиент из той же LAN обращается к внешнему IP сервера, роутеру нужен NAT loopback. Параметр `--hairpin-source` используйте только для конкретного адреса маршрутизатора, подменяющего источник соединения. Без него сервер сохраняет адрес, с которого реально пришёл клиент. Сам `--mode global` не добавляет relay и не гарантирует прохождение NAT.

Для тестов только в LAN укажите `--mode local --host 0.0.0.0 --advertise-ip 192.168.1.170` и используйте клиентский патч для этого LAN-адреса.

## Подготовить патчер

Это делает владелец сервера на Windows. Нужны Python 3, Windows PowerShell 5.1 и OpenSSL. По умолчанию используется OpenSSL из Git for Windows; другой путь можно передать через `-OpenSslPath`.

Из корня репозитория, для новой сети:

```powershell
.\patcher\tools\New-CommunityPatch.ps1 `
  -ClientPath C:\CleanSkype\Skype.exe `
  -KeysDirectory C:\SkyData\keys `
  -ServerIp 176.101.124.66 `
  -OutputDirectory .\patcher\dist\community `
  -GenerateKeys
```

Для существующего сервера укажите каталог с его ключами и уберите `-GenerateKeys`. Полные существующие связки ключей используются повторно. Если меняете адрес сервера, пакет нужно собрать заново. Выходная папка должна быть новой.

Скрипт создаёт папку `community` и архив `community.zip`. Пользователям передаётся ZIP: в нём инструменты и публичные изменения для точного оригинального EXE. Приватных ключей, профилей и полного клиента Skype в пакете нет. Резервные копии ключей храните отдельно. Если ключи когда-либо попадали в публичную историю Git, перед открытым развёртыванием замените их и пересоберите клиентские пакеты.

## Отладка

Чтобы получить подробный журнал, добавьте `--detailed-debug` к команде запуска сервера. В Linux вывод можно сохранить через `2>&1 | tee skyserver.log`. Сначала проверьте сообщения о загрузке ключей и открытии портов: ошибка привязки порта может оставить часть сервисов недоступной.

Для проверки протокола используем два отдельных профиля Skype. Локальная проверка помогает воспроизвести ошибку, а для WAN нужен второй ПК в другой сети, например через мобильный Интернет. Проверяйте по очереди вход, поиск, добавление контакта, статусы, сообщения и звонок. Записывайте время каждого действия, чтобы сопоставить его с журналом.

Если установлен Wireshark, список интерфейсов можно получить так:

```powershell
& 'C:\Program Files\Wireshark\dumpcap.exe' -D
Get-Process Skype | Select-Object Id, Path
```

Захват конкретного клиента делает [Capture-SkypeTraffic.ps1](patcher/tools/Capture-SkypeTraffic.ps1). Передайте его PID, NPF-идентификатор интерфейса из `dumpcap -D`, путь к `profile\shared.xml` и IP сервера:

```powershell
.\patcher\tools\Capture-SkypeTraffic.ps1 `
  -SkypeProcessId 1234 -Interfaces '\Device\NPF_{INTERFACE_GUID}' `
  -SharedConfigPath 'C:\SkypePatched\profile\shared.xml' `
  -ServerIp 176.101.124.66 -Seconds 60
```

Замените PID, интерфейс и путь своими значениями. Для сообщений и звонков собирайте трафик с обеих сторон. Журналы, захваты и базы могут содержать данные аккаунтов, не добавляйте их в публичный репозиторий.

Проверки Go-сервера после сборки, из `server/go`:

```sh
SKYSERVER_BLOB_WORKER="$PWD/bin/skype_blob_worker" go test ./...
```

Проверки патчера из корня репозитория:

```powershell
python -m unittest discover -s patcher/tests -p test_client_patch.py -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\patcher\tests\Test-PublicPatch.ps1
```

Инструменты для отдельных лабораторных профилей, просмотра статусов и сборки клиента остались в `patcher/tools`. C#-референс собирается через `server/csharp/build.ps1 -Test`; требования к Visual Studio и нативным помощникам описаны в [инструкции C#-сервера](server/csharp/DEPLOYMENT.md).

## Где что лежит

- [server/go](server/go/README.md) - сервер для Linux и подробности реализации.
- [server/csharp](server/csharp/README.md) - C#-референс и прежние эксперименты.
- `server/native` - нативные помощники протокола.
- [patcher](patcher/README.md) - пользовательский патчер и инструменты сборки.
- `skypeopensource2`, `skypeproto` - исходные материалы и старые исследования протокола.
- [WAN_CHECKPOINT.md](server/go/WAN_CHECKPOINT.md) - подтверждённые результаты и оставшиеся этапы WAN.
- [CALL_AUDIO.md](server/csharp/CALL_AUDIO.md) - разбор отсутствующего звука и план проверки звонков.

Некоторые старые отчёты описывают состояние на дату эксперимента. Текущий статус собран в этом README и WAN checkpoint. Бинарники Skype, ключи, базы и профили в исходниках не хранятся.
