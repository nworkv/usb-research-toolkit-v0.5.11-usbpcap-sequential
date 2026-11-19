# Сверка эмулируемых USB-устройств с USBPcap

## Идентификатор в профиле

При создании кампании `usb-gadget-campaign.py` назначает каждому case уникальные `campaign_id`, `device_id` и строковый USB serial вида `URTK-<campaign_id>-<case>`. В Device Descriptor хранится только индекс `iSerialNumber`. Сам текст serial появляется на стороне хоста только если Windows запрашивает соответствующий String Descriptor.

## Разбор Windows USBPcap

Для USBPcap PCAPNG с linktype `249` `report-usb-campaign.py` читает PCAPNG напрямую. Первые шесть packet records по умолчанию исключаются **до декодирования и построения сессий** (`--skip-host-packets 6`). USBPcap `SETUP` и `COMPLETE` пары связываются по `IRP ID`; `Control transfer stage` отличает Setup/Data/Status/Complete. Это не зависит от заполнения `usb.urb_type` или названий полей TShark.

Новая enumeration-сессия фиксируется при следующем `GET_DESCRIPTOR(Device)` после завершённого успешного `SET_CONFIGURATION` предыдущей сессии. USB bus/address используется для сопровождения сессии, но не как постоянная идентичность устройства: адрес может повторно использоваться. В текущем режиме кампании эмулируется строго одно устройство за раз.

## Алгоритм сопоставления при несинхронизированных часах

Для USBPcap linktype `249` режим `auto` выбирает `sequential`:

1. Cases упорядочиваются по номеру case; USB-сессии — по номеру первого PCAP frame.
2. Для каждой пары case/session сравниваются VID/PID, полный Device Descriptor, Configuration Descriptor, HID Report Descriptor и фактически наблюдённые endpoint payloads.
3. Монотонное выравнивание последовательностей выбирает только соответствия, которые являются уникальными в оптимальном выравнивании.
4. Если один профиль однозначно соответствует одной сессии, она назначается case. Если несколько вариантов равноценны либо сессию можно пропустить без ухудшения оптимального выравнивания, результат остаётся `AMBIGUOUS`/`UNMATCHED`.
5. Raw Gadget trace и USBPcap сопоставляются уже внутри назначенного case: descriptor responses — по точному SETUP tuple и порядку запросов; data transfers — по endpoint, направлению, payload и порядку кадров.

В этом алгоритме **не используются** `started_epoch`, `ended_epoch`, `frame.time_epoch` и разница времени Windows/Raspberry Pi. Временной режим можно включить отдельно для других типов захвата, но он требует синхронизации/калибровки.

Серийный номер, если он фактически прочитан, — дополнительный сильный идентификатор. Если Windows не запросила строку `iSerialNumber`, код не считает `SERIAL_REQUEST_NOT_OBSERVED` несовпадением и не пытается подменять его нулём или серийником из профиля.

## Статусы

- `MATCH_EXACT` / `MATCHED` — профильный отпечаток однозначно сопоставлен с сессией.
- `MATCH_AMBIGUOUS` / `AMBIGUOUS_SEQUENCE_MATCH` — несколько равнозначных соответствий.
- `RECEIVED_AND_CONFIGURED` — сессия видна в USBPcap и завершила ненулевой `SET_CONFIGURATION`.
- `RECEIVED_ENUMERATION_INCOMPLETE` — сессия видна, но успешный `SET_CONFIGURATION` не подтверждён.
- `HOST_SESSION_FOUND_CASE_IDENTITY_UNRESOLVED` — USB-сессия в захвате есть, но её связь с конкретным case не доказана.
- `NOT_OBSERVED_IN_PCAP` — после исключения первых packet records не восстановлено ни одной подходящей USB-сессии.
- `CANCELLED` — незавершённый endpoint URB отменён; отображается отдельно от descriptor/configuration ошибки.
- `TEARDOWN_ABORT_PIPE` — Windows отправила `URB_FUNCTION_ABORT_PIPE`; это событие остановки endpoint, а не payload transfer.

## Ограничения интерпретации

`NOT_OBSERVED_IN_PCAP` не доказывает `BLOCK`. Для доказательства решения фильтра нужен его отдельный журнал `ALLOW/BLOCK`, связанный с `device_id`/serial или с запуском case. Если фильтр пропустил устройство, но профильные отпечатки двух case идентичны, сопоставление без serial или журнала фильтра может остаться неоднозначным. Код намеренно не назначает в таком случае случайную сессию.

Успешный `SET_CONFIGURATION` означает, что host stack завершил этот запрос. Это не доказывает загрузку class driver или работоспособность функции устройства. USBPcap показывает host-stack/URB наблюдения, а не электрические ACK/NAK/CRC на проводе.
