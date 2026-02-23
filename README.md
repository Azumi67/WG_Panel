
- اگر دوست داشتید پنل را تست کنید و مشکلات را مطرح کنید تا بررسی کنم
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
- سپس با کامند wgpanel میتوانید اسکریپت را اجرا کنید
```
wgpanel
```
نصب node بر روی سرور با اسکریپت:

```
sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh)"'
```
- سپس با کامند node میتوانید اسکریپت را اجرا کنید
```
node
```
------------------------------------ 

  ![6348248](https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/398f8b07-65be-472e-9821-631f7b70f783)
**آموزش نصب پنل با اسکریپت**

 <div align="right">
  <details>
    <summary><strong><img src="https://github.com/Azumi67/Rathole_reverseTunnel/assets/119934376/fcbbdc62-2de5-48aa-bbdd-e323e96a62b5" alt="Image"> </strong>نحوه نصب با install everything</summary>

------------------
- پس از انکه گزینه install everything را انتخاب کردید نخست پیش نیاز ها را نصب میکند و از شما سوال میکند که پروژه را clone کند یا خیر
- وقتی که گزینه clone را بزنید باید مسیر directory را بدهید. به صورت پیش فرض مسیر /usr/local/bin است. من به صورت دیفالت مسیر را تغییر نمیدهم
- سپس میخواهد venv و پیش نیاز ها را نصب کند. گزینه y را وارد میکنم
- سپس input های .env پرسش میشود که به شرح زیر میتوانید وارد نمایید
- نخست کلید های fernet, flask & api به صورت رندوم generate میشود که میتوانید enter کنید
- دیتابیس url و log level هم میتوانید به صورت دیفالت enter کنید
- قسمت secure cookies برای استفاده از https است که من گزینه 1 را وارد میکنم
- توکن setup برای وقتی هست که شما میخواهید برای پنل register انجام دهید و انجا باید این توکن را وارد نمایید
- مسیر وایرگارد و tg_heartbeat را هم میتوانید به صورت پیش فرض enter نمایید
- سپس از شما میپرسد که ایا این همان چیزی هست که وارد کردید و یک live preview به شما نشان میدهد. اگر درست است گزینه y را وارد میکنم
- سپس کانفیگ وایرگارد را پیکربندی میکند.
- گزینه y را وارد نمایید و حالا باید گانفیگ وایرگارد را بسازیم که طبق اسکریپت برای ساختن اینترفیس جدید باید N را وارد نمایم. از من نام اینترفیس سوال میشود که به صورت پیش فرض باید قرار داد. wg0, wg1 و ..
- پرایوت ایپی ادرس برای این اینترفیس انتخاب میکنم ( دقت نمایید که این ایپی بلاک نباشد) و هم چنین پورت هم وارد میکنم
- سپس گزینه y را وارد نمایید تا دستورات iptables وارد شود و هم چنین اینترفیس سرور را وارد نمایید که معمولا eth و ens و .. است
- سپس کلید های مربوطه به وایرگارد را نشان میدهد و اگر همه چی درست باشد باید گزینه y را بزنید تا اینترفیس مربوطه ذخیره شود
- سپس تنظیمات panel را کانفیگ میکنم. بنابراین گزینه y را وارد میکنم.
- برای پنل گزینه tls را فعال میکنم. برای اینکار باید ساب دامین مربوطه هم وارد نمایم. پورت https که معمولا 443 است را وارد میکنم و گزینه y را وارد میکنم تا ذخیره شود.
- سپس runtime را کانفیگ میکنم. اگر tls را انتخاب کردید این قسمت به صورت اتوماتیک کانفیگ میشود. بنابراین وقتی از شما سوال میشود که به صورت اتوماتیک tls در runtime فعال شود میتوانید گزینه y را وارد نمایید چون قبلا tls را فعال کرده ام.
- سپس سرویس های مربوطه ساخته میشود و از شما میخواهد در صورت نیاز تلگرام بات را کانفیگ کنید که من y را وارد میکنم.
- بات توکن را که از botfather گرفته ام وارد میکنم و برای دسترسی به بات هم باید ادمین id و یوزر نیم را وارد نمایم. همچنین notification ها را فعال میکنم. توجه کنید که ادمینی که ساختید mute نکنید. ( سوال پرسیده میشود)
- گزینه mute را n وارد میکنم و تنظیمات telegram را ذخیره میکنم
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
 
