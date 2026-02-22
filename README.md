
-  نوشتن اموزش با تصاویر کمی زمان بر خواهد بود
- درصورت تمایل به تست و بررسی پنل، میتوانید مشکلاتی اگر در پنل دیدید در issue بیان کنید که برطرف بشود

![R (2)](https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/a064577c-9302-4f43-b3bf-3d4f84245a6f)
نام پروژه : پنل وایرگارد
---------------------------------------------------------------

![check](https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/13de8d36-dcfe-498b-9d99-440049c0cf14)
**امکانات**
- دارای dashboard با نمایش جزییات سرور و پنل
- مدیریت peers در پنل که شامل edit, reset time, reset usage, template & short links, more information میشود
- ایجاد node و مدیریت ان در پنل اصلی که شامل تمام گزینه های پنل اصلی برای node میشود
- اسکریپت جداگانه برای کانفیگ پنل اصلی و node
- بک اپ از سرور اصلی در پنل و بک اپ node به وسیله اسکریپت در node server مربوطه
- قسمت مخصوص برای بگ اپ گیری به صورت manual و auto و ریستور ان به چندین صورت
- نمایش اخرین بک اپ در backup tab
- نمایش لاگ برای پنل و بات و ادمین بات
- قسمت settings که شامل فعال کردن https,hsts,redirect http>https و تنشطیمات بات و اضافه کردن ادمین، بات توکن است
- قسمت settings هم چنین شامل تنظیمات interface است
- در قسمت settings هم چنین میتوانید برای short link ها از template هایی که موجود است انتخاب نمایید
- دارای بات که همچنین میتوانید peer های پنل و node را از ان طریق مدیریت کنید.
- امکان auto backup از طریق بات و ریستور ان از همان طریق
- امکان backup از طریق پنل و دانلود بر روی سیستم
- فعلا برای نود نمایش لاگ و بک اپ گیری و ریستور ان تنها از طریق اسکریپت موجود است تا بعدا در پنل اضافه شود
- امکان اضافه کردن شماره تلفن و ایدی تلگرام به هر Peer در پنل و Node
- امکان استفاده از پنل و shortlink ها و node در سرور های دیگر ( باید بک اپ هر سرور و node چداگانه به سرور های جدید copy شود و دوباره با اسکریپت اقدام به نصب پنل و node ها بکنید 
------------
نصب پنل با اسکریپت :

```
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/wg.sh)"'
```
نصب node بر روی سرور با اسکریپت:

```
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh)"'
```
-----------------------
![images](https://github.com/user-attachments/assets/f50ecb83-2194-4b91-9594-00d310dc506a)
اسکرین شات:

<details>
  <summary align="right">داشبورد پنل</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/47ce2474-5fa4-4512-a4ca-fe175d0fe119" alt="menu screen" />
  </p>
</details>

<details>
  <summary align="right">peers</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/82149141-f648-4c07-ad73-22e8a3fa9d68" alt="menu screen" />
  </p>
</details>

<details>
  <summary align="right">logs</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/afc5b0dc-068f-4b9c-b287-d90b7e838881" alt="menu screen" />
  </p>
</details>

<details>
  <summary align="right">Quick & telegram backups</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/611cf337-4703-4c2c-987d-e6104b45f51f" alt="menu screen" />
  </p>
</details>

<details>
  <summary align="right">Settings>Telegram section</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/bc528b71-9225-49f2-aa48-1ec14c56d8db" alt="menu screen" />
  </p>
</details>

<details>
  <summary align="right">Settings>telegram bot</summary>

  <p align="right">
    <img src="https://github.com/user-attachments/assets/5671ed52-9135-4184-b3e6-7f18e80ea059" alt="menu screen" />
  </p>
</details>

---------------------------------------------------------------
 
