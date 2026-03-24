# 1C Cloud Probe

GUI-приложение для первичной диагностики доступа к облачной 1С.

## Возможности
- ввод URL, логина и пароля;
- проверка доступности стартовой страницы;
- вывод цепочки редиректов;
- проверка типовых путей:
  - `/odata/`
  - `/odata/standard.odata/`
  - `/hs/`
  - `/api/`
  - `/e1cib/`
- попытка Basic Auth;
- сохранение результатов в файлы.

## Выходные файлы
В выбранной папке создаются:
- `probe.log`
- `report.json`
- `start_page.html`
- `basic_auth_page.html` (если запрос выполнен)

## Локальный запуск из Python

```bash
pip install -r requirements.txt
python app.py
