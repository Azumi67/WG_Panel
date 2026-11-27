<h1 align="right" dir="rtl">
  <img src="https://github.com/Azumi67/PrivateIP-Tunnel/assets/119934376/a064577c-9302-4f43-b3bf-3d4f84245a6f" width="45" align="absmiddle" alt="Flower">
  <bdi dir="ltr">WG Panel — v3.0.0</bdi>
</h1>

<div dir="rtl" align="right">

<p dir="rtl" align="right">پنل مدیریت <bdi dir="ltr">WireGuard</bdi> بر پایه <bdi dir="ltr">Flask</bdi>، برای مدیریت متمرکز <bdi dir="ltr">Peer</bdi>ها، <bdi dir="ltr">Interface</bdi>ها، <bdi dir="ltr">Subscription</bdi>ها و <bdi dir="ltr">Node</bdi>ها. در نسخه <bdi dir="ltr">3.0.0</bdi>، علاوه بر امکانات قبلی، از <bdi dir="ltr">PostgreSQL</bdi>، سیستم <bdi dir="ltr">Reseller</bdi>، سه نوع <bdi dir="ltr">Telegram Bot</bdi> مستقل، <bdi dir="ltr">Developer API</bdi> و <bdi dir="ltr">Background Worker</bdi>های جداگانه استفاده شده است.</p>

</div>

<p align="right" dir="ltr"><a href="https://github.com/Azumi67/WG_Panel/releases">Releases</a> · <a href="https://github.com/Azumi67/WG_Panel/issues">Issues</a> · <a href="LICENSE">License</a></p>

<h2 dir="rtl" align="right">اطلاعیه مهم قبل از <bdi dir="ltr">Update</bdi></h2>

<div dir="rtl" align="right">

<p dir="rtl" align="right"><strong>قبل از <bdi dir="ltr">Update</bdi> سرور اصلی، حتماً نسخه <bdi dir="ltr">3.0.0</bdi> را روی یک <bdi dir="ltr">VPS</bdi> آزمایشی یا کپی ایزوله از نصب فعلی خود تست کنید.</strong></p>

<p dir="rtl" align="right">این نسخه یک تغییر اساسی در <bdi dir="ltr">Backend</bdi> پنل است و <bdi dir="ltr">Database</bdi> اصلی از <bdi dir="ltr">SQLite</bdi> به <bdi dir="ltr">PostgreSQL</bdi> تغییر کرده است. هدف این تغییر، مدیریت بهتر درخواست‌های هم‌زمان، کاهش <bdi dir="ltr">Database Lock</bdi> و بهبود عملکرد پنل، <bdi dir="ltr">Reseller Workspace</bdi> و <bdi dir="ltr">Telegram Bot</bdi>ها است.</p>

<p dir="rtl" align="right">برای کاربران قدیمی، دو روش در نظر گرفته شده است: اجرای <code dir="ltr">migrate.sh</code> از نسخه کامل جدید (روش پیشنهادی) یا استفاده از <bdi dir="ltr">Update Center</bdi> که در نصب‌های استاندارد، <bdi dir="ltr">Automatic Migration</bdi> را هنگام اولین <bdi dir="ltr">Startup</bdi> آغاز می‌کند. اگر <bdi dir="ltr">PostgreSQL</bdi> و سرویس‌های لازم قبلاً به‌درستی تنظیم شده باشند، مراحل غیرضروری دوباره اجرا نمی‌شوند.</p>

<p dir="rtl" align="right">در تست عملی انجام‌شده با <bdi dir="ltr">Update Center</bdi> نسخه قدیمی، <bdi dir="ltr">PostgreSQL</bdi> نصب شد، اطلاعات <bdi dir="ltr">SQLite</bdi> با موفقیت <bdi dir="ltr">Import</bdi> و <bdi dir="ltr">Verify</bdi> شد و چهار سرویس مستقل جدید ایجاد شدند. پس از رفع رکورد <bdi dir="ltr">Cutover</bdi> قبلی در <bdi dir="ltr">VPS</bdi> آزمایشی و اجرای <bdi dir="ltr">Retry</bdi>، این فرایند حدود پنج دقیقه طول کشید. این تست روی دیتابیس کوچک انجام شده است و تضمینی برای تمام نصب‌های قدیمی، سفارشی یا پرترافیک نیست.</p>

<p dir="rtl" align="right">هنگام <bdi dir="ltr">Migration</bdi> ممکن است دسترسی به پنل و <bdi dir="ltr">Bot</bdi>ها موقتاً قطع شود. قبل از شروع، یک <bdi dir="ltr">Snapshot</bdi> کامل از <bdi dir="ltr">VPS</bdi> و <bdi dir="ltr">Backup</bdi> قابل بازیابی تهیه کنید و به <bdi dir="ltr">SSH</bdi> دسترسی داشته باشید. راهنمای کامل در بخش <b><bdi dir="ltr">Update</bdi> و <bdi dir="ltr">Migration</bdi> به <bdi dir="ltr">PostgreSQL</bdi></b> در همین <bdi dir="ltr">README</bdi> قرار دارد.</p>

</div>

---

<h2 dir="rtl" align="right">امکانات <bdi dir="ltr">WG Panel</bdi></h2>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Dashboard</bdi> و مدیریت سرور</h3>

<p dir="rtl" align="right">▪&nbsp; نمایش وضعیت <bdi dir="ltr">CPU</bdi>، <bdi dir="ltr">RAM</bdi>، <bdi dir="ltr">Disk</bdi>، <bdi dir="ltr">Network</bdi> و اطلاعات <bdi dir="ltr">WireGuard</bdi> در <bdi dir="ltr">Dashboard</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش وضعیت <bdi dir="ltr">Interface</bdi>ها، <bdi dir="ltr">Peer</bdi>ها، مصرف حجم و وضعیت اتصال کاربران و <bdi dir="ltr">Node</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; رابط <bdi dir="ltr">Modern</bdi> و <bdi dir="ltr">Legacy</bdi> با <bdi dir="ltr">Dark Mode</bdi>، <bdi dir="ltr">Light Mode</bdi> و <bdi dir="ltr">Auto Mode</bdi>؛ طراحی <bdi dir="ltr">Responsive</bdi> برای <bdi dir="ltr">Desktop</bdi> و <bdi dir="ltr">Mobile</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش وضعیت عملیات و سرویس‌ها، دسترسی به <bdi dir="ltr">Logs</bdi>، تنظیمات <bdi dir="ltr">Runtime</bdi> و <bdi dir="ltr">Update Center</bdi> از داخل پنل.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Peer</bdi> و <bdi dir="ltr">Interface Management</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; مدیریت کامل <bdi dir="ltr">Peer</bdi>ها در <bdi dir="ltr">Local Server</bdi> و <bdi dir="ltr">Node</bdi>ها: <bdi dir="ltr">Create</bdi>، <bdi dir="ltr">Bulk Create</bdi>، <bdi dir="ltr">Edit</bdi>، <bdi dir="ltr">Enable</bdi>، <bdi dir="ltr">Disable</bdi>، <bdi dir="ltr">Delete</bdi>، <bdi dir="ltr">Reset Usage</bdi> و <bdi dir="ltr">Reset Timer</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; دریافت <bdi dir="ltr">Config</bdi>، <bdi dir="ltr">QR Code</bdi>، <bdi dir="ltr">Short Link</bdi>، <bdi dir="ltr">Logs</bdi> و اطلاعات هر <bdi dir="ltr">Peer</bdi>؛ جست‌وجو و فیلتر کاربران.</p>

<p dir="rtl" align="right">▪&nbsp; تعیین <bdi dir="ltr">Data Limit</bdi>، <bdi dir="ltr">Time Limit</bdi>، <bdi dir="ltr">Start Timer on First Use</bdi> و حالت <bdi dir="ltr">Unlimited</bdi> برای مشتریان مجاز.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش مصرف حجم، زمان باقی‌مانده، وضعیت <bdi dir="ltr">Online/Offline</bdi> و وضعیت دسترسی کاربر.</p>

<p dir="rtl" align="right">▪&nbsp; افزودن شماره تلفن و <bdi dir="ltr">Telegram ID</bdi> برای <bdi dir="ltr">Peer</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; ساخت، فعال یا غیرفعال کردن و حذف <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">WireGuard</bdi> در <bdi dir="ltr">Local Server</bdi> و <bdi dir="ltr">Node</bdi>؛ تنظیم <bdi dir="ltr">DNS</bdi>، <bdi dir="ltr">MTU</bdi>، <bdi dir="ltr">Listen Port</bdi> و <bdi dir="ltr">Start after Creation</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; ساخت خودکار تنظیمات لازم <bdi dir="ltr">WireGuard</bdi> و <bdi dir="ltr">Rule</bdi>های <bdi dir="ltr">Forward</bdi> و <bdi dir="ltr">NAT</bdi> هنگام ایجاد <bdi dir="ltr">Interface</bdi> از طریق پنل.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Advanced WireGuard Options</bdi> شامل <bdi dir="ltr">DNS</bdi>، <bdi dir="ltr">MTU</bdi>، <bdi dir="ltr">Persistent Keepalive</bdi>، <bdi dir="ltr">Allowed IPs</bdi>، <bdi dir="ltr">Server Endpoint</bdi> و <bdi dir="ltr">Fixed Client Endpoint</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; مدیریت <bdi dir="ltr">Allowed IPs</bdi>، افزودن یا حذف <bdi dir="ltr">Network</bdi> و شناسایی <bdi dir="ltr">Network</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi> برای تنظیمات <bdi dir="ltr">Client</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تعریف <bdi dir="ltr">Profile</bdi> برای <bdi dir="ltr">Peer</bdi> و <bdi dir="ltr">Subscription</bdi>، انتخاب <bdi dir="ltr">Default Profile</bdi>، <bdi dir="ltr">Apply</bdi>، <bdi dir="ltr">Edit</bdi> و <bdi dir="ltr">Delete</bdi> جهت استفاده مجدد از تنظیمات ساخت کاربران.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش <bdi dir="ltr">Reseller</bdi>های اختصاص‌یافته به هر <bdi dir="ltr">Interface</bdi> در پنل <bdi dir="ltr">Admin</bdi>؛ دسترسی <bdi dir="ltr">Admin</bdi> به <bdi dir="ltr">Interface</bdi> محدود نمی‌شود. هشدار هنگام ساخت کاربر روی <bdi dir="ltr">Interface</bdi> دارای <bdi dir="ltr">Reseller</bdi> در مسیرهای مربوط به پنل وب.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Subscription</bdi> و <bdi dir="ltr">Multi-Location</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; ساخت یک <bdi dir="ltr">Subscription</bdi> برای یک <bdi dir="ltr">Client</bdi> با چند <bdi dir="ltr">Config</bdi> از <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">Local</bdi>، <bdi dir="ltr">Node</bdi> یا ترکیبی از هر دو.</p>

<p dir="rtl" align="right">▪&nbsp; انتخاب <bdi dir="ltr">Peer</bdi>های موجود یا ایجاد <bdi dir="ltr">Peer</bdi> جدید برای <bdi dir="ltr">Location</bdi>های <bdi dir="ltr">Subscription</bdi>؛ مدیریت <bdi dir="ltr">Config</bdi>های هر <bdi dir="ltr">Subscription</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تعیین <bdi dir="ltr">Data Limit</bdi>، <bdi dir="ltr">Time Limit</bdi>، <bdi dir="ltr">Start Timer on First Use</bdi> و حالت <bdi dir="ltr">Unlimited</bdi> برای مشتریان مجاز.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش <bdi dir="ltr">Data Remaining</bdi>، <bdi dir="ltr">Time Remaining</bdi> و وضعیت دسترسی <bdi dir="ltr">Client</bdi> و <bdi dir="ltr">Config</bdi>های آن.</p>

<p dir="rtl" align="right">▪&nbsp; دریافت <bdi dir="ltr">Config</bdi> و <bdi dir="ltr">QR Code</bdi> هر <bdi dir="ltr">Location</bdi> به‌صورت جداگانه و امکان دانلود تمام <bdi dir="ltr">Config</bdi>های <bdi dir="ltr">Subscription</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Public Subscription Page</bdi> با لینک اختصاصی، وضعیت اشتراک، حجم و زمان باقی‌مانده، <bdi dir="ltr">Config</bdi>ها، <bdi dir="ltr">Download</bdi> و <bdi dir="ltr">Support</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; استفاده از <bdi dir="ltr">Profile</bdi>های ذخیره‌شده و تنظیمات <bdi dir="ltr">Advanced WireGuard</bdi> هنگام ایجاد <bdi dir="ltr">Subscription</bdi>.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Template Studio</bdi> و <bdi dir="ltr">Client Portal</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; طراحی صفحات <bdi dir="ltr">Public Peer</bdi> و <bdi dir="ltr">Subscription</bdi> با <bdi dir="ltr">Template Editor</bdi> و <bdi dir="ltr">Portal Designer</bdi>، همراه با <bdi dir="ltr">Live Preview</bdi> در <bdi dir="ltr">Desktop</bdi> و <bdi dir="ltr">Mobile</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; انتخاب <bdi dir="ltr">Layout</bdi>های مختلف، تنظیم <bdi dir="ltr">Background</bdi> و <bdi dir="ltr">Live Background</bdi>، <bdi dir="ltr">Animation</bdi>، <bdi dir="ltr">Motion</bdi>، <bdi dir="ltr">Statistics</bdi>، <bdi dir="ltr">Colors</bdi>، <bdi dir="ltr">Surface</bdi>، <bdi dir="ltr">Radius</bdi>، <bdi dir="ltr">Shadow</bdi>، <bdi dir="ltr">Density</bdi>، <bdi dir="ltr">Font Scale</bdi> و <bdi dir="ltr">Page Width</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تنظیم نمایش <bdi dir="ltr">Config</bdi>ها، تعداد ستون‌ها، ترتیب <bdi dir="ltr">Section</bdi>ها و نمایش یا مخفی کردن <bdi dir="ltr">Usage</bdi>، <bdi dir="ltr">Configs</bdi>، <bdi dir="ltr">Install WireGuard</bdi> و <bdi dir="ltr">Support</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; شخصی‌سازی <bdi dir="ltr">Header</bdi>، <bdi dir="ltr">Title</bdi>، <bdi dir="ltr">Subtitle</bdi>، <bdi dir="ltr">Header Icon</bdi>، <bdi dir="ltr">Logo Size</bdi> و <bdi dir="ltr">Alignment</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; امکان شخصی‌سازی <bdi dir="ltr">Template</bdi> برای هر <bdi dir="ltr">Client</bdi> و استفاده از تنظیمات جداگانه در <bdi dir="ltr">Workspace</bdi>های مجاز <bdi dir="ltr">Reseller</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; پشتیبانی از <bdi dir="ltr">Dark Mode</bdi>، <bdi dir="ltr">Light Mode</bdi> و <bdi dir="ltr">Auto Mode</bdi> در پنل و صفحات <bdi dir="ltr">Public</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تعریف <bdi dir="ltr">Support Link</bdi> شامل <bdi dir="ltr">Telegram</bdi>، <bdi dir="ltr">WhatsApp</bdi>، <bdi dir="ltr">Phone</bdi>، <bdi dir="ltr">Email</bdi>، <bdi dir="ltr">Website</bdi> و <bdi dir="ltr">Instagram</bdi>؛ تنها گزینه‌های تنظیم‌شده نمایش داده می‌شوند.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Node Management</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; مدیریت <bdi dir="ltr">Node</bdi>های مختلف از پنل مرکزی با <bdi dir="ltr">API Key</bdi> جداگانه برای هر <bdi dir="ltr">Node</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش <bdi dir="ltr">Online</bdi>، <bdi dir="ltr">Offline</bdi> و <bdi dir="ltr">Disabled</bdi>، تعداد <bdi dir="ltr">Peer</bdi> و <bdi dir="ltr">Interface</bdi>، <bdi dir="ltr">Search</bdi>، <bdi dir="ltr">Filter</bdi>، <bdi dir="ltr">Refresh</bdi> و <bdi dir="ltr">Test Connection</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; مدیریت <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">Node</bdi> بدون ورود مستقیم به آن سرور از طریق <bdi dir="ltr">SSH</bdi>؛ ایجاد <bdi dir="ltr">Subscription</bdi>های <bdi dir="ltr">Multi-Location</bdi> میان <bdi dir="ltr">Local Server</bdi> و <bdi dir="ltr">Node</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; پشتیبانی از <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">Node</bdi> در تخصیص منابع <bdi dir="ltr">Reseller</bdi>، به شرط سازگاری نسخه <bdi dir="ltr">Node Agent</bdi> و فعال بودن مجوزهای مربوطه.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Update</bdi> مستقل <bdi dir="ltr">Node Agent</bdi> از <bdi dir="ltr">Update Center</bdi> و اسکریپت جداگانه برای نصب و مدیریت <bdi dir="ltr">Node</bdi>.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Reseller System</bdi> و <bdi dir="ltr">Plan Management</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; ساخت <bdi dir="ltr">Reseller Account</bdi> به‌صورت مستقیم توسط <bdi dir="ltr">Admin</bdi> یا پس از بررسی و تأیید سفارش <bdi dir="ltr">Plan</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تعریف <bdi dir="ltr">Plan</bdi> با <bdi dir="ltr">Price</bdi>، <bdi dir="ltr">Currency</bdi>، <bdi dir="ltr">Duration</bdi>، <bdi dir="ltr">Shared Traffic</bdi>، <bdi dir="ltr">Peer Limit</bdi> و <bdi dir="ltr">Subscription Limit</bdi>؛ امکان انتخاب <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi> که <bdi dir="ltr">Reseller</bdi> مجاز به استفاده از آن‌ها است.</p>

<p dir="rtl" align="right">▪&nbsp; هر <bdi dir="ltr">Location</bdi> در <bdi dir="ltr">Subscription</bdi> از ظرفیت <bdi dir="ltr">Peer</bdi> استفاده می‌کند و مشتریان <bdi dir="ltr">Reseller</bdi> از <bdi dir="ltr">Traffic Allowance</bdi> مشترک <bdi dir="ltr">Plan</bdi> استفاده می‌کنند.</p>

<p dir="rtl" align="right">▪&nbsp; تعیین <bdi dir="ltr">Server Host</bdi>، <bdi dir="ltr">Server Port</bdi>، امکان تغییر <bdi dir="ltr">Endpoint</bdi>، <bdi dir="ltr">Fixed Client Endpoint</bdi> و <bdi dir="ltr">Internal Network Preset</bdi> برای هر <bdi dir="ltr">Plan</bdi> یا <bdi dir="ltr">Account</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تعیین <bdi dir="ltr">Workspace Permissions</bdi> برای <bdi dir="ltr">Dashboard</bdi>، <bdi dir="ltr">Peers</bdi>، <bdi dir="ltr">Subscriptions</bdi>، <bdi dir="ltr">Create</bdi>، <bdi dir="ltr">Bulk</bdi>، <bdi dir="ltr">Edit</bdi>، <bdi dir="ltr">Delete</bdi>، <bdi dir="ltr">Pause/Enable</bdi>، <bdi dir="ltr">Reset Usage</bdi>، <bdi dir="ltr">Reset Timer</bdi> و مدیریت <bdi dir="ltr">Config</bdi>های <bdi dir="ltr">Subscription</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; مجوز جداگانه برای <bdi dir="ltr">Network Options</bdi>، انتخاب <bdi dir="ltr">Client IP</bdi> آزاد، <bdi dir="ltr">Profile</bdi>ها، <bdi dir="ltr">Peer Template</bdi>، <bdi dir="ltr">Subscription Portal</bdi>، <bdi dir="ltr">Config Download</bdi>، <bdi dir="ltr">QR Code</bdi>، <bdi dir="ltr">Rotate Link</bdi>، <bdi dir="ltr">Logs</bdi>، <bdi dir="ltr">Export</bdi>، <bdi dir="ltr">Backup</bdi> و <bdi dir="ltr">Restore</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تنظیم <bdi dir="ltr">Request Budget</bdi> برای <bdi dir="ltr">Refresh</bdi>، <bdi dir="ltr">Write</bdi> و <bdi dir="ltr">Create</bdi>، حداکثر <bdi dir="ltr">Batch Size</bdi> و تعداد <bdi dir="ltr">Saved Profile</bdi>ها. این محدودیت‌ها معادل سهمیه اختصاصی <bdi dir="ltr">CPU</bdi> یا <bdi dir="ltr">RAM</bdi> برای هر <bdi dir="ltr">Reseller</bdi> نیستند.</p>

<p dir="rtl" align="right">▪&nbsp; مدیریت تمدید اعتبار، وضعیت <bdi dir="ltr">Account</bdi>، منابع و مصرف <bdi dir="ltr">Plan</bdi> از بخش <bdi dir="ltr">Resellers</bdi>؛ کنترل دسترسی <bdi dir="ltr">Workspace</bdi> و <bdi dir="ltr">Telegram</bdi> به‌صورت جداگانه.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش نام <bdi dir="ltr">Reseller</bdi> کنار <bdi dir="ltr">Interface</bdi> و امکان انتخاب <bdi dir="ltr">Admin Only</bdi>، <bdi dir="ltr">Resellers Only</bdi> یا <bdi dir="ltr">All Customers</bdi> در بخش <bdi dir="ltr">Peers</bdi> و <bdi dir="ltr">Subscriptions</bdi> بر اساس <bdi dir="ltr">Ownership</bdi> واقعی مشتریان.</p>

<p dir="rtl" align="right">▪&nbsp; مشاهده <bdi dir="ltr">Customer Inventory</bdi> هر <bdi dir="ltr">Reseller</bdi> از <bdi dir="ltr">Manage Account → Customers</bdi> همراه با <bdi dir="ltr">Search</bdi>، <bdi dir="ltr">Filter</bdi> و <bdi dir="ltr">Pagination</bdi>؛ نمایش <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">Config</bdi>های <bdi dir="ltr">Subscription</bdi> متعلق به همان <bdi dir="ltr">Account</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Admin</bdi> همچنان به مدیریت <bdi dir="ltr">Interface</bdi>ها دسترسی دارد؛ تخصیص <bdi dir="ltr">Interface</bdi> به <bdi dir="ltr">Reseller</bdi> به معنی قفل کردن آن برای <bdi dir="ltr">Admin</bdi> یا انتقال خودکار <bdi dir="ltr">Ownership</bdi> کاربران قبلی نیست.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Reseller Workspace</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; لینک ورود اختصاصی برای هر <bdi dir="ltr">Reseller</bdi>، با امکان مدیریت دسترسی و تنظیمات امنیتی <bdi dir="ltr">Account</bdi> از پنل <bdi dir="ltr">Admin</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Dashboard</bdi> اختصاصی برای وضعیت <bdi dir="ltr">Plan</bdi>، <bdi dir="ltr">Traffic Usage</bdi>، زمان باقی‌مانده، تعداد <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">Subscription</bdi>ها و منابع موجود.</p>

<p dir="rtl" align="right">▪&nbsp; صفحات <bdi dir="ltr">Peers</bdi> و <bdi dir="ltr">Subscriptions</bdi> با طراحی هماهنگ با پنل اصلی و نمایش فقط امکاناتی که <bdi dir="ltr">Admin</bdi> مجاز کرده است.</p>

<p dir="rtl" align="right">▪&nbsp; ساخت تکی یا <bdi dir="ltr">Bulk</bdi>، مدیریت دسترسی و محدودیت‌های مشتریان، <bdi dir="ltr">Config</bdi>، <bdi dir="ltr">QR Code</bdi> و لینک‌ها مطابق مجوزهای <bdi dir="ltr">Account</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; امکان استفاده از <bdi dir="ltr">Profile</bdi>، <bdi dir="ltr">Template Editor</bdi> و <bdi dir="ltr">Portal Designer</bdi> مستقل برای مشتریان <bdi dir="ltr">Reseller</bdi> در صورت داشتن مجوز.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Activity</bdi> و <bdi dir="ltr">Logs</bdi> مربوط به <bdi dir="ltr">Account</bdi>؛ جداسازی اطلاعات و مشتریان <bdi dir="ltr">Reseller</bdi>ها با <bdi dir="ltr">Ownership Check</bdi> در <bdi dir="ltr">Backend</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تنظیمات امنیتی <bdi dir="ltr">Workspace</bdi> شامل <bdi dir="ltr">2FA</bdi> و <bdi dir="ltr">Recovery Code</bdi>، مدیریت دسترسی <bdi dir="ltr">Telegram</bdi> و <bdi dir="ltr">Application Key</bdi> بر اساس مجوزها.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Backup</bdi> رمزنگاری‌شده برای مشتریان متعلق به همان <bdi dir="ltr">Account</bdi> و قابلیت <bdi dir="ltr">Restore</bdi> در محدوده <bdi dir="ltr">Ownership</bdi> و <bdi dir="ltr">Quota</bdi>؛ این <bdi dir="ltr">Backup</bdi> جایگزین <bdi dir="ltr">Backup</bdi> کامل <bdi dir="ltr">Database</bdi> و تنظیمات سرور نیست.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Telegram Bots</bdi> و <bdi dir="ltr">Plan Shop</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; مدیریت <bdi dir="ltr">Peer</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi> از طریق <bdi dir="ltr">Admin Bot</bdi> مستقل؛ شامل <bdi dir="ltr">Search</bdi>، <bdi dir="ltr">Create</bdi>، <bdi dir="ltr">Edit</bdi>، <bdi dir="ltr">Enable</bdi>، <bdi dir="ltr">Disable</bdi>، <bdi dir="ltr">Reset</bdi>، <bdi dir="ltr">Delete</bdi>، دریافت <bdi dir="ltr">Config</bdi> و <bdi dir="ltr">QR Code</bdi>، مدیریت <bdi dir="ltr">Profile</bdi>ها و عملیات <bdi dir="ltr">Backup/Restore</bdi> پشتیبانی‌شده.</p>

<p dir="rtl" align="right">▪&nbsp; امکان تعریف چند <bdi dir="ltr">Admin</bdi> در <bdi dir="ltr">Bot</bdi>، تنظیم <bdi dir="ltr">Notification</bdi>ها و دریافت پیام‌های مربوط به <bdi dir="ltr">Panel</bdi> و <bdi dir="ltr">Node</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; هر <bdi dir="ltr">Reseller</bdi> می‌تواند با مجوز <bdi dir="ltr">Admin</bdi>، از <bdi dir="ltr">Reseller Management Bot</bdi> و <bdi dir="ltr">Bot Token</bdi> اختصاصی استفاده کند. دسترسی <bdi dir="ltr">Bot</bdi> به مشتریان همان <bdi dir="ltr">Workspace</bdi> محدود است و فرمان‌ها بر اساس <bdi dir="ltr">Workspace Permissions</bdi> و <bdi dir="ltr">Telegram Grants</bdi> فعال می‌شوند.</p>

<p dir="rtl" align="right">▪&nbsp; ساخت <bdi dir="ltr">Peer</bdi> و پیگیری وضعیت درخواست‌های <bdi dir="ltr">Queue</bdi> از طریق <bdi dir="ltr">Telegram</bdi>، همراه با <bdi dir="ltr">Operation Reference</bdi> و <bdi dir="ltr">Check Status</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش <bdi dir="ltr">Plan</bdi>های فعال، ثبت سفارش و تمدید، نمایش <bdi dir="ltr">Payment Instructions</bdi> و ارسال رسید پرداخت برای بررسی <bdi dir="ltr">Admin</bdi> از طریق <bdi dir="ltr">Plan Shop Bot</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; بررسی رسیدها و <bdi dir="ltr">Approve</bdi> یا <bdi dir="ltr">Reject</bdi> سفارش‌ها توسط <bdi dir="ltr">Admin</bdi>، همراه با ثبت اطلاعات پرداخت و وضعیت تحویل. تأیید پرداخت به‌صورت دستی انجام می‌شود و به معنی وجود <bdi dir="ltr">Payment Gateway</bdi> خودکار نیست.</p>

<p dir="rtl" align="right">▪&nbsp; ارسال اعلان‌های خرید، وضعیت تحویل، اعتبار و منابع <bdi dir="ltr">Account</bdi> و اعلان‌های مربوط به مشتریان بر اساس تنظیمات و مجوزهای فعال.</p>

<p dir="rtl" align="right">▪&nbsp; مدیریت <bdi dir="ltr">Bot</bdi>ها در بخش <bdi dir="ltr">Telegram</bdi>، مشاهده وضعیت اتصال و <bdi dir="ltr">Delivery</bdi>، امکان <bdi dir="ltr">Retry</bdi> پیام‌ها و بررسی <bdi dir="ltr">Logs</bdi>؛ پشتیبانی از زبان فارسی و <bdi dir="ltr">English</bdi> در <bdi dir="ltr">Reseller Bot</bdi> و <bdi dir="ltr">Shop Bot</bdi>.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Developer API</bdi> و <bdi dir="ltr">External Applications</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; مستندات <bdi dir="ltr">API Docs</bdi> داخل پنل، همراه با دسته‌بندی <bdi dir="ltr">Endpoint</bdi>ها، <bdi dir="ltr">Search</bdi>، نمونه درخواست با <bdi dir="ltr">cURL</bdi>، <bdi dir="ltr">Python</bdi>، <bdi dir="ltr">Node.js</bdi> و <bdi dir="ltr">PHP</bdi> و فایل <bdi dir="ltr">OpenAPI 3.0.3</bdi> برای <bdi dir="ltr">Bot Application API</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; امکان اتصال <bdi dir="ltr">Custom Bot</bdi> یا <bdi dir="ltr">External Application</bdi> به <bdi dir="ltr">Admin</bdi>، <bdi dir="ltr">Plan Shop</bdi> و <bdi dir="ltr">Workspace</bdi>های مجاز از طریق <bdi dir="ltr">Application Key</bdi> جداگانه.</p>

<p dir="rtl" align="right">▪&nbsp; تعریف <bdi dir="ltr">Named Application</bdi>، <bdi dir="ltr">Scope</bdi>، <bdi dir="ltr">Expiry</bdi>، <bdi dir="ltr">IP/CIDR Allowlist</bdi>، محدودیت درخواست و امکان <bdi dir="ltr">Rotate</bdi> یا <bdi dir="ltr">Revoke</bdi> کردن <bdi dir="ltr">Credential</bdi> بر اساس سیاست <bdi dir="ltr">Admin</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; ذخیره <bdi dir="ltr">Digest</bdi> کلیدهای <bdi dir="ltr">Application</bdi> به‌جای نمایش مداوم <bdi dir="ltr">Secret</bdi>؛ کلید جدید هنگام صدور یا <bdi dir="ltr">Rotate</bdi> ارائه می‌شود.</p>

<p dir="rtl" align="right">▪&nbsp; اعمال <bdi dir="ltr">Ownership</bdi>، <bdi dir="ltr">Account Permissions</bdi>، <bdi dir="ltr">Telegram Grants</bdi> و <bdi dir="ltr">Request Budget</bdi> روی درخواست‌های <bdi dir="ltr">API</bdi> مربوط به <bdi dir="ltr">Reseller</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; نمونه <bdi dir="ltr">Custom Reseller Bot</bdi> در مسیر <bdi dir="ltr">examples/custom_reseller_bot.py</bdi> برای توسعه‌دهندگان؛ از <bdi dir="ltr">Token</bdi> مستقل و <bdi dir="ltr">HTTPS</bdi> استفاده کنید.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">PostgreSQL</bdi> و <bdi dir="ltr">Background Services</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; استفاده از <bdi dir="ltr">PostgreSQL</bdi> به‌عنوان <bdi dir="ltr">Database</bdi> اصلی برای پنل، <bdi dir="ltr">Peer</bdi>ها، <bdi dir="ltr">Subscription</bdi>ها، <bdi dir="ltr">Reseller</bdi>ها، <bdi dir="ltr">Plan Shop</bdi> و وضعیت عملیات.</p>

<p dir="rtl" align="right">▪&nbsp; تفکیک <bdi dir="ltr">Web Panel</bdi>، <bdi dir="ltr">Admin Telegram Bot</bdi>، <bdi dir="ltr">Reseller Workspace Bots</bdi>، <bdi dir="ltr">Plan Shop</bdi>، <bdi dir="ltr">Provisioning</bdi> و <bdi dir="ltr">Usage Monitoring</bdi> در سرویس‌های مستقل.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Durable Provisioning Queue</bdi> برای ثبت عملیات ساخت مشتریان <bdi dir="ltr">Reseller</bdi>، پیگیری وضعیت، جلوگیری از اجرای هم‌زمان ناسازگار و مدیریت درخواست‌های نامطمئن پس از قطعی.</p>

<p dir="rtl" align="right">▪&nbsp; نمایش <bdi dir="ltr">Operation History</bdi> و وضعیت <bdi dir="ltr">Queue</bdi>، همراه با امکان بررسی عملیات نیازمند <bdi dir="ltr">Admin Review</bdi>؛ عملیات نامطمئن بدون بررسی دوباره اجرا نمی‌شوند.</p>

<p dir="rtl" align="right">▪&nbsp; استفاده از <bdi dir="ltr">Transaction</bdi> و <bdi dir="ltr">Lock</bdi>های <bdi dir="ltr">PostgreSQL</bdi> برای هماهنگی عملیات حساس، بدون حذف کنترل‌های لازم برای تخصیص <bdi dir="ltr">IP</bdi> و تغییر <bdi dir="ltr">WireGuard</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Automatic Startup Migration</bdi> برای نصب‌های قدیمی استاندارد، نصب <bdi dir="ltr">PostgreSQL</bdi> در صورت نیاز، <bdi dir="ltr">Backup</bdi> و بررسی <bdi dir="ltr">Data Import</bdi> و آماده‌سازی <bdi dir="ltr">Worker</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Idempotent Startup</bdi> برای <bdi dir="ltr">Skip</bdi> کردن <bdi dir="ltr">Migration</bdi> و نصب مجدد سرویس‌های سازگار؛ جلوگیری از <bdi dir="ltr">Migration</bdi> مجدد روی دیتابیس قدیمی پس از <bdi dir="ltr">Cutover</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">PostgreSQL Manager</bdi>، ابزارهای بررسی <bdi dir="ltr">Database Contention</bdi> و <bdi dir="ltr">Resource Pressure</bdi>، وضعیت سرویس‌ها و امکان <bdi dir="ltr">Restart All Panel Services</bdi> از <bdi dir="ltr">CLI</bdi>.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Backup</bdi>، <bdi dir="ltr">Restore</bdi> و <bdi dir="ltr">Logs</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; امکان تهیه <bdi dir="ltr">Manual Backup</bdi> و <bdi dir="ltr">Auto Backup</bdi>، دانلود فایل <bdi dir="ltr">Backup</bdi>، ارسال به <bdi dir="ltr">Telegram</bdi> بر اساس تنظیمات و بررسی فایل با <bdi dir="ltr">Inspect</bdi> قبل از <bdi dir="ltr">Restore</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تهیه <bdi dir="ltr">Backup</bdi> از <bdi dir="ltr">Database</bdi>، <bdi dir="ltr">Settings</bdi>، <bdi dir="ltr">Subscription</bdi>ها، <bdi dir="ltr">Short Link</bdi>ها، <bdi dir="ltr">Profile</bdi>ها، <bdi dir="ltr">Interface</bdi>ها، <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">WireGuard Config</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi>، در محدوده امکانات پشتیبانی‌شده.</p>

<p dir="rtl" align="right">▪&nbsp; تهیه <bdi dir="ltr">Backup</bdi> مخصوص <bdi dir="ltr">PostgreSQL</bdi> با <bdi dir="ltr">pg_dump</bdi> و بررسی ساختار <bdi dir="ltr">Archive</bdi>. برای انتقال پنل به سرور جدید می‌توان از <bdi dir="ltr">Full Backup</bdi> استفاده کرد؛ مراحل <bdi dir="ltr">Restore</bdi> باید جداگانه و پس از بررسی سازگاری انجام شوند.</p>

<p dir="rtl" align="right">▪&nbsp; امکان <bdi dir="ltr">Settings-only Restore</bdi> داخل پنل؛ برای <bdi dir="ltr">PostgreSQL DB Backup</bdi> یا <bdi dir="ltr">Full Backup</bdi> باید از <bdi dir="ltr">Offline Restore</bdi> استفاده کنید. عملیات <bdi dir="ltr">Live Database Restore</bdi> در <bdi dir="ltr">PostgreSQL</bdi> غیرفعال است.</p>

<p dir="rtl" align="right">▪&nbsp; تهیه <bdi dir="ltr">Backup</bdi> رمزنگاری‌شده برای مشتریان هر <bdi dir="ltr">Reseller</bdi>. فایل <bdi dir="ltr">ZIP</bdi> مربوط به <bdi dir="ltr">Admin</bdi> به‌صورت کامل رمزنگاری نمی‌شود و باید در محل امن نگهداری شود.</p>

<p dir="rtl" align="right">▪&nbsp; مشاهده <bdi dir="ltr">Logs</bdi> مربوط به <bdi dir="ltr">Panel</bdi>، <bdi dir="ltr">Telegram Bot</bdi>، <bdi dir="ltr">Admin</bdi>، <bdi dir="ltr">Interface</bdi>، <bdi dir="ltr">Reseller</bdi> و عملیات، همراه با <bdi dir="ltr">Search</bdi>، <bdi dir="ltr">Filter</bdi>، <bdi dir="ltr">Level</bdi>، <bdi dir="ltr">Auto Refresh</bdi>، <bdi dir="ltr">Local Time</bdi>، <bdi dir="ltr">Humanize</bdi> و <bdi dir="ltr">Export</bdi> به <bdi dir="ltr">CSV</bdi> یا <bdi dir="ltr">NDJSON</bdi> در بخش‌های پشتیبانی‌شده.</p>

<p dir="rtl" align="right">▪&nbsp; بررسی <bdi dir="ltr">Update Log</bdi>، وضعیت <bdi dir="ltr">Background Worker</bdi>ها و <bdi dir="ltr">Logs</bdi> مربوط به <bdi dir="ltr">Migration</bdi> از طریق <bdi dir="ltr">systemd</bdi> و <bdi dir="ltr">journalctl</bdi>.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Traffic Control</bdi> و <bdi dir="ltr">Security</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; تعریف <bdi dir="ltr">Traffic Control Policy</bdi> اختصاصی برای هر <bdi dir="ltr">Peer</bdi> با استفاده از <bdi dir="ltr">nftables</bdi> و محدود کردن مقصد بر اساس <bdi dir="ltr">Domain</bdi>، <bdi dir="ltr">IP/CIDR</bdi> یا <bdi dir="ltr">Country</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; اعمال <bdi dir="ltr">Policy</bdi> روی <bdi dir="ltr">Peer</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi>، مدیریت خودکار <bdi dir="ltr">Rule</bdi>ها، نمایش <bdi dir="ltr">Target</bdi>های مسدودشده و <bdi dir="ltr">Geo Blocking</bdi> بر اساس <bdi dir="ltr">Country Code</bdi> و مجموعه <bdi dir="ltr">IP</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; ابزار <bdi dir="ltr">Policy Check</bdi> و <bdi dir="ltr">Test Destination</bdi> برای بررسی <bdi dir="ltr">Rule</bdi>ها و مقصد؛ نمایش <bdi dir="ltr">Counter</bdi> مربوط به <bdi dir="ltr">Packet</bdi> و <bdi dir="ltr">Traffic</bdi> مسدودشده با <bdi dir="ltr">Humanize</bdi> حجم از <bdi dir="ltr">Byte</bdi> تا <bdi dir="ltr">TiB</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">HTTP Security Monitor</bdi> برای مشاهده درخواست‌های مشکوک با <bdi dir="ltr">IP</bdi>، <bdi dir="ltr">Path</bdi>، <bdi dir="ltr">Method</bdi>، <bdi dir="ltr">Status Code</bdi> و تعداد <bdi dir="ltr">Request</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; حالت <bdi dir="ltr">Monitor Only</bdi> یا <bdi dir="ltr">Monitor</bdi> + <bdi dir="ltr">Block</bdi>، <bdi dir="ltr">Temporary Block</bdi> با مدت قابل تنظیم، <bdi dir="ltr">Unblock</bdi> خودکار، <bdi dir="ltr">Trusted CIDR</bdi> و <bdi dir="ltr">Notification</bdi>های <bdi dir="ltr">Telegram</bdi> مربوط به شناسایی و <bdi dir="ltr">Block/Unblock</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Admin Login</bdi>، تغییر <bdi dir="ltr">Username</bdi> و <bdi dir="ltr">Password</bdi> و <bdi dir="ltr">2FA</bdi> با <bdi dir="ltr">TOTP</bdi>، <bdi dir="ltr">QR Code</bdi>، <bdi dir="ltr">Manual Key</bdi> و <bdi dir="ltr">Recovery Code</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تنظیم <bdi dir="ltr">HTTPS</bdi>، <bdi dir="ltr">Domain</bdi>، <bdi dir="ltr">HTTPS Port</bdi>، <bdi dir="ltr">Certificate</bdi>، <bdi dir="ltr">Private Key</bdi>، <bdi dir="ltr">HTTP → HTTPS Redirect</bdi> و <bdi dir="ltr">HSTS</bdi>؛ تنظیم <bdi dir="ltr">Trusted Proxy/Host</bdi> برای نصب‌های پشت <bdi dir="ltr">Reverse Proxy</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; کنترل دسترسی و جداسازی <bdi dir="ltr">Reseller</bdi>ها در <bdi dir="ltr">Backend</bdi>، <bdi dir="ltr">CSRF Protection</bdi> و محدودیت درخواست‌ها؛ این امکانات جایگزین به‌روزرسانی سیستم‌عامل، <bdi dir="ltr">Firewall</bdi> و نگهداری امن <bdi dir="ltr">Secret</bdi>ها نیستند.</p>

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Settings</bdi>، <bdi dir="ltr">Update Center</bdi> و <bdi dir="ltr">CLI</bdi></h3>

<p dir="rtl" align="right">▪&nbsp; تنظیم <bdi dir="ltr">Panel Runtime</bdi> شامل <bdi dir="ltr">Port</bdi>، <bdi dir="ltr">Worker</bdi>، <bdi dir="ltr">Thread</bdi> و <bdi dir="ltr">Timeout</bdi> و امکان <bdi dir="ltr">Restart</bdi> پنل از داخل <bdi dir="ltr">Settings</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; تنظیم <bdi dir="ltr">Interface</bdi>ها، <bdi dir="ltr">Endpoint</bdi>ها، <bdi dir="ltr">Regional Settings</bdi>، <bdi dir="ltr">Telegram Bot Token</bdi>، <bdi dir="ltr">Admin</bdi>ها و <bdi dir="ltr">Notification</bdi>ها.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Update Center</bdi> برای بررسی نسخه و <bdi dir="ltr">Update</bdi> پنل اصلی و <bdi dir="ltr">Node Agent</bdi>ها، نمایش پیشرفت عملیات، <bdi dir="ltr">Code Snapshot</bdi> و <bdi dir="ltr">Recovery/Restore</bdi> در مسیرهای پشتیبانی‌شده.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Rollback</bdi> کد با <bdi dir="ltr">Database Rollback</bdi> یکسان نیست؛ پس از <bdi dir="ltr">PostgreSQL Cutover</bdi> نباید بدون بررسی داده‌ها به <bdi dir="ltr">SQLite</bdi> یا کد ناسازگار برگردید.</p>

<p dir="rtl" align="right">▪&nbsp; اسکریپت‌های جداگانه نصب <bdi dir="ltr">Panel</bdi> و <bdi dir="ltr">Node</bdi> شامل <bdi dir="ltr">Virtual Environment</bdi>، <bdi dir="ltr">Requirements</bdi>، <bdi dir="ltr">WireGuard</bdi>، <bdi dir="ltr">.env</bdi>، <bdi dir="ltr">Runtime</bdi> و <bdi dir="ltr">Telegram</bdi>.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">CLI</bdi> با دستور <bdi dir="ltr">wgpanel</bdi> برای نصب، مدیریت سرویس‌ها و <bdi dir="ltr">PostgreSQL Manager</bdi> و دستور <bdi dir="ltr">node</bdi> برای مدیریت <bdi dir="ltr">Node</bdi>؛ امکان <bdi dir="ltr">Restart</bdi> تمام سرویس‌های پنل با تأیید <bdi dir="ltr">Admin</bdi>.</p>

</div>

---

<div dir="rtl" align="right">

<h2 dir="rtl" align="right"><bdi dir="ltr">Update</bdi> و <bdi dir="ltr">Migration</bdi> به <bdi dir="ltr">PostgreSQL</bdi></h2>

<h3 dir="rtl" align="right">قبل از شروع</h3>

<p dir="rtl" align="right">▪&nbsp; یک <bdi dir="ltr">Snapshot</bdi> کامل <bdi dir="ltr">VPS</bdi> و <bdi dir="ltr">Backup</bdi> مستقل و قابل بازیابی از <bdi dir="ltr">Database</bdi>، پوشه <bdi dir="ltr">instance</bdi>، فایل <bdi dir="ltr">.env</bdi>، کلیدهای رمزنگاری و تنظیمات <bdi dir="ltr">WireGuard</bdi> تهیه کنید.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Update</bdi> را ابتدا در محیط آزمایشی انجام دهید و از صحت اطلاعات <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">Client</bdi>ها، <bdi dir="ltr">Subscription</bdi>ها، <bdi dir="ltr">Admin Login</bdi> و عملکرد <bdi dir="ltr">Bot</bdi>ها مطمئن شوید.</p>

<p dir="rtl" align="right">▪&nbsp; برای <bdi dir="ltr">Migration</bdi>، <bdi dir="ltr">Maintenance Window</bdi> مناسب در نظر بگیرید. ممکن است پنل و <bdi dir="ltr">Bot</bdi>ها موقتاً از دسترس خارج شوند. <bdi dir="ltr">Migration</bdi> به‌صورت عمدی <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">WireGuard</bdi> را متوقف نمی‌کند، اما عدم قطعی <bdi dir="ltr">VPN</bdi> در تمام شرایط تضمین نمی‌شود.</p>

<p dir="rtl" align="right">▪&nbsp; کلیدهای <bdi dir="ltr">FLASK_SECRET_KEY</bdi>، <bdi dir="ltr">FERNET_KEY</bdi> و <bdi dir="ltr">API_KEY</bdi> را تغییر ندهید. <bdi dir="ltr">DATABASE_URL</bdi> را قبل از <bdi dir="ltr">Import</bdi> و <bdi dir="ltr">Verification</bdi> به‌صورت دستی تغییر ندهید.</p>

<p dir="rtl" align="right">▪&nbsp; راهنمای زیر برای نصب معمول <bdi dir="ltr">Ubuntu/Debian</bdi> با <bdi dir="ltr">systemd</bdi>، دسترسی <bdi dir="ltr">root</bdi> و <bdi dir="ltr">Database instance/wg_panel.db</bdi> است. نصب‌های <bdi dir="ltr">Docker</bdi>، <bdi dir="ltr">Database</bdi> خارجی، مسیرهای سفارشی و چند نصب روی یک سرور نیازمند بررسی جداگانه هستند.</p>

<p dir="rtl" align="right">▪&nbsp; اگر <bdi dir="ltr">PostgreSQL</bdi> و سرویس‌های جدید از قبل تنظیم شده‌اند، <bdi dir="ltr">SQLite Migration</bdi> را دوباره اجرا نکنید. <bdi dir="ltr">Backup</bdi> بگیرید و از مسیر معمول <bdi dir="ltr">Update</bdi> استفاده کنید.</p>

<h3 dir="rtl" align="right">روش اول: <bdi dir="ltr">Manual Migration</bdi> با <bdi dir="ltr">migrate.sh</bdi> (پیشنهادی)</h3>

<p dir="rtl" align="right">اسکریپت <bdi dir="ltr">migrate.sh</bdi> باید همراه با فایل‌های کامل نسخه جدید اجرا شود. دانلود و اجرای تنها فایل <bdi dir="ltr">migrate.sh</bdi> روی یک نسخه قدیمی کافی نیست.</p>

<p dir="rtl" align="right">دستورهای زیر برای نسخه منتشرشده روی <bdi dir="ltr">main</bdi> هستند. ابتدا روی <bdi dir="ltr">VPS</bdi> آزمایشی اجرا کنید. اگر مسیر نصب <bdi dir="ltr">/usr/local/bin/WG_Panel</bdi> یا مسیر دیگری است، مقدار <bdi dir="ltr">PANEL</bdi> را مطابق نصب تغییر دهید. ترجیحاً از <bdi dir="ltr">Release Archive</bdi> یا <bdi dir="ltr">Commit</bdi> بررسی‌شده استفاده کنید.</p>

</div>

<div dir="ltr" align="left">

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates rsync

PANEL=/usr/local/bin/WGPanel
WORK=$(mktemp -d)
mkdir -p "$WORK/release"

curl --fail --location --retry 3 --proto '=https' \
  "https://codeload.github.com/Azumi67/WG_Panel/tar.gz/refs/heads/main" \
  -o "$WORK/release.tar.gz" &&
tar -xzf "$WORK/release.tar.gz" -C "$WORK/release" --strip-components=1
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">مرحله بالا فقط فایل‌های نسخه جدید را در مسیر جداگانه دانلود و <bdi dir="ltr">Extract</bdi> می‌کند. پس از بررسی فایل‌های دانلودشده، در همان ترمینال دو دستور زیر را اجرا کنید. گزینه <code dir="ltr">--check</code> تنظیمات نصب و سرویس‌ها را بررسی می‌کند و گزینه <code dir="ltr">--inspect</code> سازگاری ساختار <bdi dir="ltr">SQLite</bdi> را بدون <bdi dir="ltr">Import</bdi> بررسی می‌کند:</p>

</div>

<div dir="ltr" align="left">

```bash
sudo bash "$WORK/release/migrate.sh" --upgrade --project "$PANEL" --check
sudo bash "$WORK/release/migrate.sh" --upgrade --project "$PANEL" --inspect
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">در صورت موفقیت بررسی‌ها، پس از تهیه <bdi dir="ltr">Backup</bdi> و در <bdi dir="ltr">Maintenance Window</bdi>، دستور زیر را اجرا کنید. برای تأیید، عبارت <bdi dir="ltr">MIGRATE</bdi> را وارد کنید.</p>

</div>

<div dir="ltr" align="left">

```bash
sudo bash "$WORK/release/migrate.sh" --upgrade --project "$PANEL"
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">اسکریپت <bdi dir="ltr">PostgreSQL</bdi> را در صورت نیاز نصب می‌کند، سرویس‌هایی را که در <bdi dir="ltr">Database</bdi> می‌نویسند متوقف می‌کند، <bdi dir="ltr">Backup</bdi> امن می‌گیرد و اطلاعات را <bdi dir="ltr">Import</bdi> و <bdi dir="ltr">Verify</bdi> می‌کند، فایل‌های نسخه جدید را نصب می‌کند و پس از <bdi dir="ltr">Verify</bdi> شدن <bdi dir="ltr">Import</bdi>، <bdi dir="ltr">DATABASE_URL</bdi> را تغییر می‌دهد. <bdi dir="ltr">Startup Upgrade</bdi> پنل نیز سرویس‌های لازم را بررسی می‌کند. <bdi dir="ltr">Database SQLite</bdi> قبلی حذف نمی‌شود.</p>

<p dir="rtl" align="right">اگر فایل‌های جدید از قبل نصب شده‌اند ولی هنوز <bdi dir="ltr">SQLite</bdi> فعال است، فقط در صورت نبود عملیات <bdi dir="ltr">Migration</bdi> در حال اجرا و پس از بررسی وضعیت قبلی می‌توانید از دستورات زیر استفاده کنید:</p>

</div>

<div dir="ltr" align="left">

```bash
cd /usr/local/bin/WGPanel
sudo bash migrate.sh --check
sudo bash migrate.sh --inspect
sudo bash migrate.sh
```

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right">روش دوم: <bdi dir="ltr">Automatic Migration</bdi> از طریق <bdi dir="ltr">Update Center</bdi></h3>

<p dir="rtl" align="right">در نسخه منتشرشده روی <bdi dir="ltr">main</bdi>، نصب‌های قدیمی می‌توانند مانند قبل از <bdi dir="ltr">Update Center</bdi> نسخه جدید را دریافت کنند. در نصب استاندارد، <bdi dir="ltr">app.py</bdi> در اولین اجرا <bdi dir="ltr">SQLite</bdi> را تشخیص می‌دهد و <bdi dir="ltr">Migration</bdi> و آماده‌سازی سرویس‌ها را به یک سرویس مستقل <bdi dir="ltr">systemd</bdi> واگذار می‌کند. نیاز به تأیید دستی <bdi dir="ltr">MIGRATE</bdi> نیست.</p>

<p dir="rtl" align="right">اگر <bdi dir="ltr">PostgreSQL</bdi> و سرویس‌های مورد نیاز از قبل تنظیم شده باشند، مراحل نصب و انتقال غیرضروری تکرار نمی‌شوند. اگر وضعیت نصب ناسازگار باشد یا سابقه <bdi dir="ltr">Cutover</bdi> قبلی وجود داشته باشد، سیستم ممکن است برای جلوگیری از آسیب به اطلاعات متوقف شود و نیاز به بررسی <bdi dir="ltr">Admin</bdi> داشته باشد.</p>

<p dir="rtl" align="right">در صورت نیاز به غیرفعال کردن <bdi dir="ltr">Automatic Migration</bdi>، گزینه <code dir="ltr">WG_AUTO_UPGRADE=0</code> در محیط سرویس باید قبل از <bdi dir="ltr">Startup</bdi> تنظیم شده باشد؛ این گزینه جایگزین <bdi dir="ltr">Migration</bdi> نیست و پنل جدید با <bdi dir="ltr">SQLite</bdi> در حالت عادی اجرا نمی‌شود.</p>

<p dir="rtl" align="right">حین <bdi dir="ltr">Migration</bdi>، پنل را دوباره نصب نکنید، سرویس‌ها را دستی <bdi dir="ltr">Restart</bdi> نکنید و اسکریپت <bdi dir="ltr">Migration</bdi> دیگری اجرا نکنید. هنگام نصب بسته‌های <bdi dir="ltr">APT</bdi> ممکن است چند دقیقه پیام جدیدی در <bdi dir="ltr">Log</bdi> ظاهر نشود.</p>

<p dir="rtl" align="right">توجه: <bdi dir="ltr">Update Center</bdi> نسخه قدیمی مستقیماً از <bdi dir="ltr">main</bdi> دانلود می‌کند. حتی در صورت <bdi dir="ltr">Pre-release</bdi> بودن <bdi dir="ltr">Tag</bdi>، تغییر <bdi dir="ltr">main</bdi> برای کاربران قدیمی قابل دریافت است.</p>

<h2 dir="rtl" align="right">مشاهده <bdi dir="ltr">Logs</bdi> هنگام <bdi dir="ltr">Update</bdi> و <bdi dir="ltr">Migration</bdi></h2>

<p dir="rtl" align="right">از <bdi dir="ltr">Update log</bdi> در <bdi dir="ltr">Update Center</bdi> یا از طریق <bdi dir="ltr">SSH</bdi> استفاده کنید. در صورت قطع دسترسی به پنل، <bdi dir="ltr">SSH</bdi> بهترین راه بررسی است.</p>

</div>

<div dir="ltr" align="left">

```bash
sudo journalctl -u 'wg-panel-update-panel-*' -n 200 --no-pager
sudo journalctl -u 'wg-maintenance-upgrade-*' -n 200 --no-pager
sudo journalctl -u 'wg-maintenance-upgrade-*' -f
sudo journalctl -u wg-panel -n 200 --no-pager
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">نام دقیق سرویس <bdi dir="ltr">Migration</bdi> در <bdi dir="ltr">Log Startup</bdi> پنل نمایش داده می‌شود. در صورت نیاز، آن را با دستور زیر پیدا کنید و همان نام را با <bdi dir="ltr">journalctl</bdi> دنبال کنید:</p>

</div>

<div dir="ltr" align="left">

```bash
sudo systemctl list-units --all 'wg-maintenance-upgrade-*'
sudo tail -f /var/log/apt/term.log /var/log/dpkg.log
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">پیام‌های موفقیت مورد انتظار:</p>

</div>

<div dir="ltr" align="left">

```text
SUCCESS: PostgreSQL cutover completed.
Startup maintenance completed. PostgreSQL and the separated services are selected.
```

</div>

<div dir="rtl" align="right">

<h2 dir="rtl" align="right">بررسی بعد از <bdi dir="ltr">Update</bdi></h2>

</div>

<div dir="ltr" align="left">

```bash
sudo systemctl status wg-panel wg-panel-bot wg-reseller-worker \
  wg-plan-shop wg-provision wg-monitor postgresql --no-pager
pg_isready
sudo journalctl -u wg-provision -u wg-monitor -n 100 --no-pager
sudo journalctl -u wg-panel-bot -u wg-reseller-worker -u wg-plan-shop -n 100 --no-pager
```

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right">سرویس‌های پنل و کاربرد آن‌ها</h3>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-panel</bdi></strong> — پنل وب و <bdi dir="ltr">API</bdi></p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-panel-bot</bdi></strong> — <bdi dir="ltr">Admin Bot</bdi></p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-reseller-worker</bdi></strong> — <bdi dir="ltr">Bot</bdi>های مدیریت <bdi dir="ltr">Reseller</bdi>ها</p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-plan-shop</bdi></strong> — <bdi dir="ltr">Plan Shop Bot</bdi> و اعلان‌های خرید</p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-provision</bdi></strong> — صف ساخت <bdi dir="ltr">Peer</bdi> و <bdi dir="ltr">Subscription</bdi></p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">wg-monitor</bdi></strong> — کنترل مصرف و انقضا و نگهداری اطلاعات</p>

<p dir="rtl" align="right">▪&nbsp; <strong><bdi dir="ltr">postgresql</bdi></strong> — سرویس <bdi dir="ltr">Database</bdi> محلی</p>

<p dir="rtl" align="right"><bdi dir="ltr">Admin Bot</bdi> ممکن است بنا بر تنظیمات شما غیرفعال باشد. وضعیت <bdi dir="ltr">PostgreSQL</bdi> را علاوه بر <bdi dir="ltr">systemctl</bdi> با <bdi dir="ltr">pg_isready</bdi> و بررسی عملکرد واقعی پنل کنترل کنید.</p>

<p dir="rtl" align="right">قبل از استفاده اصلی، <bdi dir="ltr">Admin Login</bdi> و <bdi dir="ltr">Reseller</bdi>ها، تعداد <bdi dir="ltr">Peer</bdi>ها و <bdi dir="ltr">Subscription</bdi>ها، حجم و زمان باقی‌مانده، لینک‌های قبلی، ساخت و ویرایش <bdi dir="ltr">Peer</bdi>ها، <bdi dir="ltr">Bot</bdi>های فعال، <bdi dir="ltr">Backup</bdi> و عملکرد پنل پس از <bdi dir="ltr">Restart</bdi> را تست کنید.</p>

<h2 dir="rtl" align="right"><bdi dir="ltr">Troubleshooting</bdi> و <bdi dir="ltr">Recovery</bdi> در صورت خطای <bdi dir="ltr">Migration</bdi></h2>

<p dir="rtl" align="right"><bdi dir="ltr">Backup</bdi>های <bdi dir="ltr">Migration</bdi> در مسیر زیر ذخیره می‌شوند:</p>

</div>

<div dir="ltr" align="left">

```text
/var/backups/wgpanel/postgresql-cutover/
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">ابتدا <bdi dir="ltr">Log</bdi> خطا را بررسی کنید. پس از رفع مشکل و اطمینان از اینکه <bdi dir="ltr">Migration</bdi> دیگری در حال اجرا نیست، برای تلاش مجدد <bdi dir="ltr">Startup Upgrade</bdi> در نصب استاندارد:</p>

</div>

<div dir="ltr" align="left">

```bash
cd /usr/local/bin/WGPanel
sudo venv/bin/python scripts/startup_upgrade.py --retry
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">اگر خطای <bdi dir="ltr">previous PostgreSQL cutover</bdi> مشاهده شد، وضعیت <bdi dir="ltr">Migration</bdi> قبلی یا <bdi dir="ltr">Database</bdi> را برای دور زدن این خطا حذف نکنید. این بررسی برای جلوگیری از جایگزینی داده‌های جدید <bdi dir="ltr">PostgreSQL</bdi> با <bdi dir="ltr">SQLite</bdi> قدیمی است. پس از <bdi dir="ltr">Cutover</bdi>، بازگرداندن صرف کد قدیمی یا انتخاب مجدد <bdi dir="ltr">SQLite</bdi> یک <bdi dir="ltr">Rollback</bdi> ایمن محسوب نمی‌شود.</p>

<p dir="rtl" align="right">در <bdi dir="ltr">PostgreSQL</bdi>، <bdi dir="ltr">Online Restore</bdi> برای <bdi dir="ltr">DB/Full Backup</bdi> غیرفعال است؛ <bdi dir="ltr">Database Restore</bdi> را در حالت <bdi dir="ltr">Offline</bdi>، در یک <bdi dir="ltr">Database</bdi> خالی و جداگانه انجام دهید و قبل از تغییر اتصال پنل، نتیجه را <bdi dir="ltr">Verify</bdi> کنید. <bdi dir="ltr">Backup</bdi>ها ممکن است شامل کلیدها و اطلاعات محرمانه باشند؛ آن‌ها را عمومی نکنید.</p>

<p dir="rtl" align="right">در صورت بروز مشکل، در بخش <a href="https://github.com/Azumi67/WG_Panel/issues"><bdi dir="ltr">Issues</bdi></a> نسخه قبلی و جدید، سیستم‌عامل، نوع نصب، مرحله خطا و <bdi dir="ltr">Log</bdi> مرتبط را ارسال کنید. قبل از ارسال، رمز <bdi dir="ltr">Database</bdi>، <bdi dir="ltr">DATABASE_URL</bdi> کامل، <bdi dir="ltr">API Key</bdi>، <bdi dir="ltr">Bot Token</bdi>، کلیدهای خصوصی و لینک‌های اختصاصی را حذف کنید.</p>

</div>

---

<h2 dir="rtl" align="right">نصب جدید <bdi dir="ltr">Panel</bdi></h2>

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای نصب جدید روی <bdi dir="ltr">Ubuntu/Debian</bdi>، ابتدا <bdi dir="ltr">PostgreSQL</bdi> را نصب و یک <bdi dir="ltr">Database</bdi> و <bdi dir="ltr">Role</bdi> اختصاصی ایجاد کنید. از <bdi dir="ltr">Database</bdi> عمومی یا <bdi dir="ltr">Role</bdi> با دسترسی <bdi dir="ltr">Superuser</bdi> برای پنل استفاده نکنید. این مرحله برای نصب جدید است؛ کاربران <bdi dir="ltr">SQLite</bdi> باید از راهنمای <bdi dir="ltr">Migration</bdi> بالا استفاده کنند و کاربران <bdi dir="ltr">PostgreSQL</bdi> نباید <bdi dir="ltr">Database</bdi> فعلی را دوباره ایجاد کنند.</p>

</div>

<div dir="ltr" align="left">

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates postgresql postgresql-client
sudo systemctl enable --now postgresql
sudo -u postgres createuser --pwprompt wgpanel
sudo -u postgres createdb --owner=wgpanel wgpanel
pg_isready
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">سپس اسکریپت رسمی نصب را از <bdi dir="ltr">main</bdi> دانلود کنید، محتوای آن را بررسی کنید و اجرا کنید:</p>

</div>

<div dir="ltr" align="left">

```bash
curl --fail --location --proto '=https' \
  https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/wg.sh \
  -o wg.sh
sudo bash wg.sh --force-fetch
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای ورود مجدد به <bdi dir="ltr">CLI</bdi> پنل:</p>

</div>

<div dir="ltr" align="left">

```bash
wgpanel
```

</div>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><strong>آموزش <bdi dir="ltr">Install Everything</bdi></strong></summary>

<div dir="rtl" align="right">

<p dir="rtl" align="right">۱ ـ در <bdi dir="ltr">CLI</bdi> وارد <bdi dir="ltr">Install</bdi> & <bdi dir="ltr">Setup</bdi> شوید و <bdi dir="ltr">Install Everything</bdi> را انتخاب کنید.</p>

<p dir="rtl" align="right">۲ ـ <bdi dir="ltr">System Requirements</bdi> را نصب کنید و اجازه دهید <bdi dir="ltr">Repository</bdi> پروژه <bdi dir="ltr">Clone</bdi> شود. مسیر نصب را مشخص کنید (معمولاً زیر <code dir="ltr">/usr/local/bin</code>).</p>

<p dir="rtl" align="right">۳ ـ <bdi dir="ltr">Virtual Environment</bdi> و <bdi dir="ltr">Python Requirements</bdi> را نصب کنید. <bdi dir="ltr">PostgreSQL Driver</bdi> نیز باید نصب شود.</p>

<p dir="rtl" align="right">۴ ـ در مرحله <code dir="ltr">.env</code>، کلیدهای <bdi dir="ltr">Flask</bdi>، <bdi dir="ltr">Fernet</bdi> و <bdi dir="ltr">API Key</bdi> را برای نصب جدید به‌صورت تصادفی ایجاد کنید. در نصب موجود این کلیدها را تغییر ندهید.</p>

<p dir="rtl" align="right">۵ ـ مقدار <code dir="ltr">DATABASE_URL</code> را مطابق <bdi dir="ltr">Database</bdi> و <bdi dir="ltr">Role</bdi> ایجادشده وارد کنید. مقدار نمونه در ادامه آمده است؛ <code dir="ltr">CHANGE_ME</code> را با رمز واقعی جایگزین کنید. اگر رمز شامل کاراکترهای خاص <bdi dir="ltr">URL</bdi> است، آن را <bdi dir="ltr">URL-encode</bdi> کنید. از <bdi dir="ltr">Default Placeholder</bdi> استفاده نکنید.</p>

<p dir="rtl" align="right">۶ ـ <bdi dir="ltr">Log Level</bdi>، <bdi dir="ltr">Secure Cookies</bdi>، <bdi dir="ltr">Setup Token</bdi>، <bdi dir="ltr">WireGuard Config Path</bdi> و <bdi dir="ltr">TG Heartbeat</bdi> را تنظیم کنید. برای <bdi dir="ltr">HTTPS</bdi>، <bdi dir="ltr">Secure Cookies</bdi> را فعال کنید. <bdi dir="ltr">Setup Token</bdi> برای <bdi dir="ltr">Register</bdi> اولیه <bdi dir="ltr">Admin</bdi> استفاده می‌شود؛ آن را خصوصی نگه دارید.</p>

<p dir="rtl" align="right">۷ ـ پیش‌نمایش <code dir="ltr">.env</code> را بررسی و ذخیره کنید.</p>

<p dir="rtl" align="right">۸ ـ در صورت نیاز، <bdi dir="ltr">WireGuard Interface</bdi> بسازید. نام <bdi dir="ltr">Interface</bdi> مانند <code dir="ltr">wg0</code>، یک <bdi dir="ltr">Private Subnet</bdi> بدون تداخل و <bdi dir="ltr">Listen Port</bdi> مناسب انتخاب کنید. تنظیمات <bdi dir="ltr">Forward/NAT</bdi> و <bdi dir="ltr">Network Interface</bdi> سرور (مانند <bdi dir="ltr">eth0</bdi> یا <bdi dir="ltr">ens3</bdi>) را مطابق شبکه خود وارد کنید. <bdi dir="ltr">Config</bdi> و <bdi dir="ltr">Key</bdi>ها را قبل از ذخیره بررسی کنید.</p>

<p dir="rtl" align="right">۹ ـ <bdi dir="ltr">Panel Settings</bdi> را تنظیم کنید. برای <bdi dir="ltr">HTTPS</bdi>، <bdi dir="ltr">Domain</bdi> یا <bdi dir="ltr">Subdomain</bdi> معتبر، <bdi dir="ltr">Port</bdi> (معمولاً <bdi dir="ltr">443</bdi>) و <bdi dir="ltr">Certificate</bdi> مناسب را وارد کنید.</p>

<p dir="rtl" align="right">۱۰ ـ <bdi dir="ltr">Runtime</bdi> را تنظیم کنید؛ در صورت استفاده از <bdi dir="ltr">TLS</bdi>، تنظیم <bdi dir="ltr">Runtime</bdi> باید با <bdi dir="ltr">Panel Settings</bdi> هماهنگ باشد.</p>

<p dir="rtl" align="right">۱۱ ـ <bdi dir="ltr">Panel Service</bdi> را ایجاد و فعال کنید. <bdi dir="ltr">PostgreSQL</bdi> باید قبل از <bdi dir="ltr">Startup</bdi> آماده باشد. پس از شروع پنل، صفحه <bdi dir="ltr">Register</bdi> را باز کنید و <bdi dir="ltr">Admin</bdi> را ایجاد کنید.</p>

<p dir="rtl" align="right">۱۲ ـ در صورت نیاز، <bdi dir="ltr">Telegram Bot</bdi> را با <bdi dir="ltr">Token</bdi> دریافت‌شده از <bdi dir="ltr">BotFather</bdi>، <bdi dir="ltr">Admin ID</bdi> و <bdi dir="ltr">Username</bdi> تنظیم کنید. <bdi dir="ltr">Notification</bdi>ها را بر اساس نیاز فعال کنید و <bdi dir="ltr">Admin</bdi> را ناخواسته <bdi dir="ltr">Mute</bdi> نکنید.</p>

<p dir="rtl" align="right">۱۳ ـ <bdi dir="ltr">Background Worker</bdi>ها را بررسی کنید. اگر <bdi dir="ltr">Setup</bdi> آن‌ها کامل نشده بود، از <bdi dir="ltr">Install</bdi> & <bdi dir="ltr">Setup → Background workers</bdi> استفاده کنید. وضعیت سرویس‌ها و ساخت یک <bdi dir="ltr">Peer</bdi> آزمایشی را بررسی کنید.</p>

</div>

<div dir="ltr" align="left">

```ini
DATABASE_URL=postgresql+psycopg://wgpanel:CHANGE_ME@127.0.0.1:5432/wgpanel
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای مشاهده <bdi dir="ltr">PostgreSQL Manager</bdi>، از منوی <bdi dir="ltr">CLI</bdi> استفاده کنید یا از مسیر نصب اجرا کنید:</p>

</div>

<div dir="ltr" align="left">

```bash
cd /usr/local/bin/WGPanel
sudo python3 wg-postgres.py --status
sudo python3 wg-postgres.py
```

</div>

</details>

<h2 dir="rtl" align="right">نصب <bdi dir="ltr">Node</bdi></h2>

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای نصب <bdi dir="ltr">Node</bdi>، اسکریپت زیر را روی سرور مورد نظر دانلود و بررسی کنید، سپس آن را اجرا کنید. نصب و <bdi dir="ltr">Update</bdi> مربوط به <bdi dir="ltr">Node Agent</bdi> مستقل از پنل اصلی انجام می‌شود. اسکریپت <bdi dir="ltr">Migration</bdi> مربوط به <bdi dir="ltr">Database</bdi> پنل اصلی را روی <bdi dir="ltr">Node</bdi> اجرا نکنید.</p>

</div>

<div dir="ltr" align="left">

```bash
curl --fail --location --proto '=https' \
  https://raw.githubusercontent.com/Azumi67/WG_Panel/refs/heads/main/agent/node.sh \
  -o node.sh
sudo bash node.sh
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای ورود به <bdi dir="ltr">CLI</bdi> مدیریت <bdi dir="ltr">Node</bdi>:</p>

</div>

<div dir="ltr" align="left">

```bash
node
```

</div>

<div dir="rtl" align="right">

<p dir="rtl" align="right">پس از <bdi dir="ltr">Setup</bdi>، <bdi dir="ltr">Node</bdi> را از بخش <bdi dir="ltr">Nodes</bdi> در پنل اصلی با <bdi dir="ltr">Base URL</bdi> و <bdi dir="ltr">API Key</bdi> مربوط به همان <bdi dir="ltr">Node</bdi> اضافه کنید و <bdi dir="ltr">Test Connection</bdi> را انجام دهید.</p>

</div>

---

<h2 dir="rtl" align="right">راهنمای <bdi dir="ltr">Endpoint</bdi> و <bdi dir="ltr">Advanced Network Options</bdi></h2>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Default Endpoint</bdi> برای هر <bdi dir="ltr">Interface</bdi></h3>

<p dir="rtl" align="right">آدرس <bdi dir="ltr">Server Endpoint</bdi> داخل <bdi dir="ltr">Config</bdi> کاربر معمولاً از <bdi dir="ltr">Domain</bdi> یا <bdi dir="ltr">Public IP</bdi> پنل تشخیص داده می‌شود. اگر سرور پشت <bdi dir="ltr">NAT</bdi>، <bdi dir="ltr">Reverse Proxy</bdi> یا <bdi dir="ltr">Load Balancer</bdi> است یا چند <bdi dir="ltr">IP</bdi> عمومی و <bdi dir="ltr">Domain</bdi> دارد، می‌توانید برای هر <bdi dir="ltr">Interface</bdi> یک <bdi dir="ltr">Default Endpoint</bdi> تعریف کنید.</p>

<p dir="rtl" align="right">▪&nbsp; این قابلیت برای <bdi dir="ltr">Interface</bdi>های <bdi dir="ltr">Local</bdi> و <bdi dir="ltr">Node</bdi> قابل استفاده است.</p>

<p dir="rtl" align="right">▪&nbsp; از <bdi dir="ltr">Settings → Interface</bdi> مقدار <bdi dir="ltr">Host</bdi> و <bdi dir="ltr">Port</bdi> مورد نظر را وارد کنید.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Host</bdi> می‌تواند <bdi dir="ltr">Domain</bdi> یا <bdi dir="ltr">IP</bdi> باشد؛ <bdi dir="ltr">Port</bdi> باید با <bdi dir="ltr">UDP Port</bdi> واقعی قابل دسترسی <bdi dir="ltr">WireGuard</bdi> هماهنگ باشد.</p>

<p dir="rtl" align="right">▪&nbsp; با خالی کردن <bdi dir="ltr">Host</bdi> و <bdi dir="ltr">Port</bdi>، <bdi dir="ltr">Automatic Endpoint Detection</bdi> فعال می‌شود.</p>

<p dir="rtl" align="right">▪&nbsp; <bdi dir="ltr">Default Endpoint</bdi> هنگام <bdi dir="ltr">Export Config</bdi> استفاده می‌شود. <bdi dir="ltr">Peer</bdi>هایی که <bdi dir="ltr">Endpoint</bdi> اختصاصی دارند می‌توانند مقدار مستقل خود را حفظ کنند.</p>

<p dir="rtl" align="right">▪&nbsp; تغییر <bdi dir="ltr">Default Endpoint</bdi> به‌صورت عادی <bdi dir="ltr">Peer</bdi>های قبلی را تغییر نمی‌دهد.</p>

<p dir="rtl" align="right">▪&nbsp; برای تغییر <bdi dir="ltr">Peer</bdi>های موجود از <bdi dir="ltr">Apply to existing peers</bdi> استفاده کنید و مشخص کنید فقط موارد بدون <bdi dir="ltr">Endpoint</bdi> اختصاصی تغییر کنند یا <bdi dir="ltr">Endpoint</bdi> قبلی نیز <bdi dir="ltr">Overwrite</bdi> شود.</p>

<p dir="rtl" align="right">▪&nbsp; این قابلیت هنگام تغییر <bdi dir="ltr">Domain</bdi> یا <bdi dir="ltr">Public IP</bdi> سرور کاربرد دارد.</p>

<p dir="rtl" align="right">نمونه <bdi dir="ltr">Host</bdi> و <bdi dir="ltr">Port</bdi>:</p>

</div>

<div dir="ltr" align="left">

```text
vpn.example.com
203.0.113.9
51820
```

</div>

<div dir="rtl" align="right">

<h3 dir="rtl" align="right"><bdi dir="ltr">Fixed Client Endpoint</bdi></h3>

<p dir="rtl" align="right">در حالت عادی این فیلد را خالی بگذارید. <bdi dir="ltr">Fixed Client Endpoint</bdi> با <bdi dir="ltr">Default Server Endpoint</bdi> متفاوت است و برای <bdi dir="ltr">Client</bdi>هایی است که <bdi dir="ltr">Endpoint</bdi> ثابت دارند.</p>

<p dir="rtl" align="right">▪&nbsp; برای موبایل، لپ‌تاپ، اینترنت سیم‌کارت، <bdi dir="ltr">CGNAT</bdi> و <bdi dir="ltr">Client</bdi>هایی با <bdi dir="ltr">IP</bdi> متغیر معمولاً لازم نیست.</p>

<p dir="rtl" align="right">▪&nbsp; برای <bdi dir="ltr">Client</bdi> با <bdi dir="ltr">Public IP</bdi> یا <bdi dir="ltr">DNS</bdi> ثابت، بعضی سناریوهای <bdi dir="ltr">Site-to-Site</bdi> یا <bdi dir="ltr">Gateway/Load Balancer</bdi> ثابت با <bdi dir="ltr">UDP Forwarding</bdi> قابل استفاده است.</p>

<p dir="rtl" align="right">▪&nbsp; مقدار می‌تواند <bdi dir="ltr">Domain</bdi> یا <bdi dir="ltr">IP</bdi> به همراه <bdi dir="ltr">UDP Port</bdi> باشد.</p>

<p dir="rtl" align="right">▪&nbsp; استفاده نادرست می‌تواند اتصال <bdi dir="ltr">Client</bdi> را مختل کند. فقط در صورت نیاز و با شناخت ساختار شبکه آن را تنظیم کنید.</p>

</div>

<div dir="ltr" align="left">

```text
client.example.com:51820
203.0.113.20:51820
```

</div>

---

<h2 dir="rtl" align="right"><bdi dir="ltr">Screenshots</bdi> — تصاویر پنل</h2>

<div dir="rtl" align="right">

<p dir="rtl" align="right">تصاویر زیر از نسخه‌های قبلی پنل هستند؛ ظاهر نسخه <bdi dir="ltr">3.0.0</bdi> ممکن است متفاوت باشد.</p>

</div>

<h3 dir="ltr" align="right">Modern</h3>

<details dir="rtl" align="right">
<summary dir="rtl" align="right">داشبورد پنل</summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/e3c6f410-48e1-4287-a3da-269ccc0de78a" alt="داشبورد پنل"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Peers</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/357cff7e-d64b-4db0-98ad-8f1ce9410e6a" alt="peers"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Subscription</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/edb4936c-4e13-4795-907a-98680d551695" alt="Subscription"></p>

</details>

<h3 dir="ltr" align="right">Legacy</h3>

<details dir="rtl" align="right">
<summary dir="rtl" align="right">داشبورد پنل</summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/db92ea88-3b63-4bab-a2f6-5705200799d4" alt="داشبورد پنل"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Peers</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/903ace8d-88a6-4e88-be49-4c30d7a82f98" alt="peers"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Subscription</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/e0a23cda-d94a-4c66-a47a-a20f043b8f0f" alt="Subscription"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Logs</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/afc5b0dc-068f-4b9c-b287-d90b7e838881" alt="logs"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Quick &amp; Telegram Backups</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/611cf337-4703-4c2c-987d-e6104b45f51f" alt="Quick & telegram backups"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Settings → Telegram Section</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/bc528b71-9225-49f2-aa48-1ec14c56d8db" alt="Settings>Telegram section"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Settings → Telegram Bot</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/a87617da-18e0-4065-b2ed-d38d4322958b" alt="Settings>telegram bot"></p>

</details>

<details dir="rtl" align="right">
<summary dir="rtl" align="right"><bdi dir="ltr">Template Settings</bdi></summary>

<p dir="rtl" align="right"><img src="https://github.com/user-attachments/assets/b2bfc186-ba26-4c5f-b78d-a9889e168060" alt="template settings"></p>

</details>

---

<div dir="rtl" align="right">

<p dir="rtl" align="right">برای گزارش مشکل از <a href="https://github.com/Azumi67/WG_Panel/issues"><bdi dir="ltr">Issues</bdi></a> استفاده کنید. نسخه <bdi dir="ltr">Panel</bdi> و <bdi dir="ltr">Node</bdi>، سیستم‌عامل، روش نصب و <bdi dir="ltr">Log</bdi> مرتبط را همراه گزارش ارسال کنید. هیچ <bdi dir="ltr">Secret</bdi>، <bdi dir="ltr">Password</bdi>، <bdi dir="ltr">API Key</bdi>، <bdi dir="ltr">Private Key</bdi> یا لینک اختصاصی <bdi dir="ltr">Reseller</bdi> را عمومی نکنید.</p>

</div>
