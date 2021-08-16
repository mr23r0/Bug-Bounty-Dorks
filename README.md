
<p align="center"><a href="https://laravel.com" target="_blank"><img src="https://miro.medium.com/max/602/0*EA62_VMXI5zNV8FS" width="100%"></a></p>

## <p align="center" style="color:#4285F4">Why use <i style=color:gold>Google Dorks?</i></p>
##### <i>Well, <b>Google is a very powerful tool.</b> It can not only search for Websites, Songs, Movies and Places it can do various types of things, like suppose if you want to check if a website has a directory "env", to find the answer you have to brute-force directories and it has many consiquences, Who knows firewall may block you ! And  you will also use very good amount of resources to do that...</i>

<b STYLE="Color:red">!! IF THAT DOESN'T HELP GOD MAY HELP YOU !!</b>

## <p align="center">Google Dorks To Find A Bug Hunting Program ::</p>
<b STYLE="Color:green; background-color:skyblue; margin:2px; padding:2px">To understand what is exactly happning  </b>
###### intext: will find keywords in DOM
###### site: will find similler Domain Websites
###### inurl: will search for those Domain names or urls who contain the keyword 
###### intitle: will search for those pages who contain the keyword in the page title

#### Some Google Dorks with inurl:

```code
	inurl"security report"
	inurl:/responsible-disclosure/ university
	inurl:/security ext:txt "contact"
	inurl: private bugbountyprogram
	inurl:/.well-known/security ext:txt
	inurl:/.well-known/security ext:txt intext:hackerone
	inurl:/.well-known/security ext:txt -hackerone -bugcrowd -synack -openbugbounty
	inurl:reporting-security-issues
	inurl:security-policy.txt ext:txt
	inurl:/security ext:txt "contact"
	inurl:responsible-disclosure-policy
	inurl:"bug bounty" and intext:"�" and inurl:/security
	inurl:"bug bounty" and intext:"$" and inurl:/security
	inurl:"bug bounty" and intext:"INR" and inurl:/security
	inurl:/security.txt "mailto*" -github.com  -wikipedia.org -portswigger.net -magento
	inurl: "responsible disclosure", "bug bounty", "bugbounty"
	inurl /bug bounty
	inurl : / security
	inurl:security.txt
	inurl:security "reward"
	inurl : /responsible disclosure
	inurl : /responsible-disclosure/ reward
	inurl : / responsible-disclosure/ swag
	inurl : / responsible-disclosure/ bounty
	inurl:'/responsible disclosure' hoodie
	inurl:'vulnerability-disclosure-policy' reward
	insite:"responsible disclosure" -inurl:nl
```
	
#### Dorks with intext: param
```code
	intext:responsible disclosure bounty
	intext:security report monetary inurl:security 
	intext:security report reward inurl:report
    intext:Vulnerability Disclosure site:eu
	intext:"BugBounty" and intext:"BTC" and intext:"reward"
	intext:bounty inurl:/security/trust/report-a-vulnerability
	intext:Vulnerability Disclosure site:nl
	"responsible disclosure" intext:"you may be eligible for monetary compensation"
```	
	
#### Dorks with site: Param 

<b>NOTE :: <i style="color:green">With the help of * you can easliy find subdomains.</i></b>
	
```code
	site:*.*.de inurl:bug inurl:bounty
	site:*.*.nl intext:security report reward
	site:*.*.nl intext:responsible disclosure reward
	site:*.edu intext:security report vulnerability
	site:*.*.* inurl:bug inurl:bounty
	site:help.*.* inurl:bounty
	site:security.*.* inurl: bounty
	site:*.*.uk intext:security report reward
	site:*.*.cn intext:security report reward
	site:twitter.com bug bounty swag
	site:responsibledisclosure.com
	site eu responsible disclosure
	site .nl responsible disclosure
	site responsible disclosure
	site:support.*.* intext:security report reward
	"powered by bugcrowd" -site:bugcrowd.com
	"van de melding met een minimum van een" -site:responsibledisclosure.nl
```

#### Some Other Dorks
```code
	responsible disclosure:sites
	responsible disclosure r=h:nl
	responsible disclosure r=h:uk
	responsible disclosure r=h:eu
	responsible disclosure bounty r=h:nl
	responsible disclosure bounty r=h:uk
	responsible disclosure bounty r=h:eu
	responsible disclosure swag r=h:nl
	responsible disclosure swag r=h:uk
	responsible disclosure swag r=h:eu
	responsible disclosure reward r=h:nl
	responsible disclosure reward r=h:uk
	responsible disclosure reward r=h:eu
	responsible disclosure swag r=h:com
```
	
#### Dork to Find Open Redirection 

replace target.com to your target...

```code
site:target.com inurl:rdir | inurl:url | inurl:redirect | inurl:return | inurl:redirect_uri | inurl:src=http | inurl:r=http  | inurl:uri=http | inurl:url=http
```
You can also use these with inurl:
 ```code
page
url
ret
r2
img
u
return
r
URL
next
redirect
redirectBack
AuthState
referer
redir
l
aspxerrorpath
image_path
ActionCodeURL
return_url
link
q
location
ReturnUrl
uri
referrer
returnUrl
forward
file
rb
end_display
urlact
from
goto
path
redirect_url
old
pathlocation
successTarget
returnURL
urlsito
newurl
Url
back
retour
odkazujuca_linka
r_link
cur_url
H_name
ref
topic
resource
returnTo
home
node
sUrl
href
linkurl
returnto
redirecturl
SL
st
errorUrl
media
destination
targeturl
return_to
cancel_url
doc
GO
ReturnTo
anything
FileName
logoutRedirectURL
list
startUrl
service
redirect_to
end_url
_next
noSuchEntryRedirect
context
returnurl
ref_url
/?page=
/index.php?ret=
/analytics/hit.php?r2=
/api/thumbnail?img=
/e.html?u=
/actions/act_continueapplication.cfm?r=
/redirect2/?url=
/Shibboleth.sso/Logout?return=
/ui/clear-selected/?next=
/Home/Redirect?url=
/jobs/?l=
/Error.aspx?aspxerrorpath=
/r.php?u=
/services/logo_handler.ashx?image_path=
/AddProduct.aspx?ActionCodeURL=
/tools/login/default.asp?page=
/spip.php?url=
/usermanagement/mailGeneratedPassword?referer=
/?return=
/?redir=
/simplesaml/module.php/core/loginuserpass.php?AuthState=
/out.php?url=
/affiche.php?uri=
/redirector.php?url=
/cgi/set_lang?referrer=
/blog/click?url=
/site.php?url=
/download2.php?file=
/jump.php?url=
/redirect/?redirect=
/admin/track/track?redirect=
/switch.php?rb=
/php-scripts/form-handler.php?end_display=
/cg/rk/?url=
/tosite.php?url=
/cambioidioma.php?urlact=
/accueil/spip.php?url=
/IRB/sd/Rooms/RoomComponents/LoginView/GetSessionAndBack?redirectBack=
/search?q=
/default.aspx?URL=
/initiate-sso-login/?redirect_url=
/module.php/core/loginuserpass.php?AuthState=
/authentication/check_login?old=
/RedirectToDoc.aspx?URL=
/shop/bannerhit.php?url=
/acceptcookies/?ReturnUrl=
/index.php?url=
/publang?url=
/home/helperpage?url=
/widgets.aspx?url=
/_lang/en?next=
/application/en?url=
/common/topcorm.do?pathlocation=
/main/action?successTarget=
/Videos/SetCulture?returnURL=
/Localize/ChangeLang?returnUrl=
/_goToSite.asp?urlsito=
/redir?url=
/admin/auth/logined?redirect=
/linkforward?forward=
/modules/babel/redirect.php?newurl=
/umbraco/Surface/LanguageSurface/ChangeLanguage?Url=
/langswitcher.php?url=
/redirect/?url=
/i18n/i18n_user_currencies/change_currency?back=
/accessibilite/textBackUp/?retour=
/fncBox.php?url=
/all4shop-akcie.php?odkazujuca_linka=
/openurl.php?url=
/te3/out.php?u=
/utils/set_language.html?return_url=
/trigger.php?r_link=
/home/lng?cur_url=
/goto?url=
/o.php?url=
/link-master/19/follow?link=
/hack.php?H_name=
/bmad/namhoc.php?return=
/maven/stats.asp?ref=
/Main/WebHome?topic=
/bin/fusion/imsLogin?resource=
/languechange.aspx?url=
/bloques/bannerclick.php?url=
/changesiteversion-full?referer=
/out.php?link=
/bgpage?r=
/signout?returnTo=
/switch_lang.php?return_url=
/nousername.php?redir=
/i/logout?return=
/util_goto_detail_home.cfm?home=
/misc/oldmenu.html?from=
/click.php?url=
/bitrix/rdc/?goto=
/?node=
/setLanguage.php?return=
/redirect/ad?url=
/redirect.php?sUrl=
/redirect?url=
/url?url=

````

#### Dork to Find Sensetive Files on S3 Bucket
````code
inurl:gov site:[http://s3.amazonaws.com](http://s3.amazonaws.com/)

site:[http://s3.amazonaws.com](http://s3.amazonaws.com/) confidential | top secret | classified | undisclosed
````

#### Dork to Find Sensitive Directories:
```code
"-----BEGIN PGP PRIVATE KEY BLOCK-----" ext:pem | ext:key | ext:txt -git
"-----BEGIN EC PRIVATE KEY-----" | " -----BEGIN EC PARAMETERS-----" ext:pem | ext:key | ext:txt
inurl:tcpconfig.html
inurl:/certs/server.key
inurl:print.htm intext:"Domain Name:" + "Open printable report"
inurl:/jsps/testoperation.jsp "Test Operation"
intitle:"index of" "*Maildir/new"
intitle:("Index of" AND "wp-content/plugins/boldgrid-backup/=")
"-- Dumped from database version" + "-- Dumped by pg_dump version" ext:txt | ext:sql | ext:env | ext:log
/etc/config + "index of /" /
/etc/certs + "index of /" */*
intitle:"index of" inurl:admin/download
intitle:"index of" "dump.sql"
"index of" inurl:database ext:sql | xls | xml | json | csv
ssh_host_dsa_key.pub + ssh_host_key + ssh_config = "index of / "
intitle:"index of" "*.cert.pem" | "*.key.pem"
intitle:index of .git/hooks/
intitle:"index of" "WebServers.xml"
"-- Dumping data for table `admin`" | "-- INSERT INTO `admin`" "VALUES" ext:sql | ext:txt | ext:log | ext:env
inurl: /.git
inurl:8080 + intext:"httpfileserver 2.3"
inurl:node_modules/mqtt/test/helpers/
intitle:"index of" "server.crt" | "server.csr"
intitle: "Index of" inurl:admin/uploads
intitle:"index of" "/CFIDE/" intext:"administrator"
"index of" "mysql.sh"
intitle:"index of" "slapd.conf"
intitle:"index of" "/system.log" | "/system.logs"
intitle:"Everything" inurl:C:Windows
"index of" "email.ini"
intitle:"index of" "/app.log" | "/app.logs"
"-- Dumping data for table * " ext:sql | ext:xls intext:db | intext:database | intext:password | username
GitLab ssh.log ext:log
"-- Dumping data for table `users` | `people` | `member`" ext:sql | ext:txt | ext:log | ext:env
ext:reg [HKEY_CURRENT_USERSoftwareSimonTathamPuTTYSshHostKeys]
"index of" "performance_schema"
"index of" "users.ibd"
"-- PostgreSQL database dump complete" ext:sql | ext:txt | ext:log | ext:env
"ws_ftp.log" ext:log
"-- Dump completed" ext:sql | ext:txt | ext:log
intitle:"index of" "firewall.log" | "firewall.logs"
intitle:"index of" "/000~ROOT~000/"
"Share Link" inurl:/share.cgi?ssid=
intitle:"index of" /lsass.exe
Index: /wp-includes/Text/Diff
intitle:"index of" /var/logs filetype:'"log | txt | csv"
intitle:"Index of /" +.htaccess.old
intitle:"index of" "/root/etc/security/"
intitle:"Index of c:xampp"
Google Dork : Index of: /services/aadhar card/
intitle:"index of" "app.log"
intitle:"index of" "/home/ROOT_PATH/"
"Index of" "/monitoring"
intitle:"index of" "ssh_host_ecdsa_key"
Index of: /services/pancard/
inurl:member filetype:xls
intitle:"index of" "oauth-private.key"
inurl:_vti_pvt/service.pwd
intext:"INTERNAL USE ONLY" ext:doc OR ext:pdf OR ext:xls OR ext:xlsx
inurl:admin/data* intext:index of
intitle:"index of" "admin/sql/"
"index of" "svg"
index of logs.tar
"Index of" "sass-cache"
intitle:"index of" "survey.cgi"
"index of" "fileadmin"
intitle:"Dashboard [Jenkins]"
intitle:"index of" "uploads.old"
allintitle: sensitive ext:doc OR ext:xls OR ext:xlsx
intitle:"index of" inurl:ftp intext:admin
intitle:"index of" "system/config"
intitle:"index of" "admin/config"
"index of" "/config/sql"
intitle:"index of" "api/admin"
intitle:"index of" "tinyfilemanager.php"
intitle:"index of" "test/storage/framework/sessions/"
intitle:"index of" "symfony/config"
intitle:"index of" "graphql/subscription"
intitle:"index of" "/admin/backup"
intitle:"index of" "admin/json"
intitle:"index of" "/admin_backup"
intitle:"index of" "git-jira-log"
intitle:"index of" db.frm
intitle:"index of" "/db_backups/"
intitle:"index of" "common.crt" OR "ca.crt"
intitle:"index of" "global.asa"
intitle:"index of" "proxy.pac" OR "proxy.pac.bak"
intitle: "index of" "MySQL-Router"
intitle:"index of" "owncloud/config/*"
intitle:"index of" "iredadmin/*"
intitle:"index of" "cctv"
intitle:"index of" cvsroot
intitle:"index of" "/concrete/Authentication"
intitle:"index of" "jwt-auth"
intitle:"index of" "maven-metadata.xml" "Port 80"
intitle:"index of" inurl:wp-json embedurl?
intitle:"index of" "metadata"
intitle:"index of" "apache-log-parser" "Port 80"
intitle:"index of" "config.py"
intext:"index of /" ".composer-auth.json"
inurl:"/includes/api/" intext:"index of /"
inurl:"/includes/OAuth2" intext:"index of /"
inurl:concrete/config/
intitle:"index of" "htdocs.zip"
intitle:"index of" "*php.swp"
intitle:index.of "db.zip"
intitle:index.of "backwpup"
intitle:"index of" "/Cloudflare-CPanel-7.0.1"
intitle:"index of" "sms.log"
intitle:"index of" "ftp.log"
-pool intitle:"index of" wget-log -pub
-pub -pool intitle:"index of" squirrelmail/
intitle:"index of" api_key OR "api key" OR apiKey -pool
intitle:"index of" domain.key -public
intitle:"index of" .oracle_jre_usage/
-pub -pool intitle:"index of" vagrantfile -"How to"
intitle:"index of" .zshrc~ OR .zshrc OR .zshenv OR .zshenv~ -pool -public
"key" OR key.jar intitle:"index of" webstart
index of /storage/logs/
intitle:index of "uploads"
```

#### Dork to Find XSS 
```code
/2wayvideochat/index.php?r=
/elms/subscribe.php?course_id= /elms/subscribe.php?course_id=
/gen_confirm.php?errmsg= /gen_confirm.php?errmsg=
/hexjector.php?site= /hexjector.php?site=
/index.php?option=com_easygb&Itemid=
/index.php?view=help&amp;faq=1&amp;ref=
/index.php?view=help&faq=1&ref=
/info.asp?page=fullstory&amp;key=1&amp;news_type=news&amp;onvan=
/info.asp?page=fullstory&key=1&news_type=news&onvan=
/main.php?sid= /main.php?sid=
/news.php?id= /news.php?id=
/notice.php?msg= /notice.php?msg=
/preaspjobboard//Employee/emp_login.asp?msg1=
/Property-Cpanel.html?pid= /Property-Cpanel.html?pid=
/schoolmv2/html/studentmain.php?session=
/search.php?search_keywords= /search.php?search_keywords=
/ser/parohija.php?id= /ser/parohija.php?id=
/showproperty.php?id= /showproperty.php?id=
/site_search.php?sfunction= /site_search.php?sfunction=
/strane/pas.php?id= /strane/pas.php?id=
/vehicle/buy_do_search/?order_direction=
/view.php?PID= /view.php?PID=
/winners.php?year=2008&amp;type= /winners.php?year=2008&amp;type=
/winners.php?year=2008&type= /winners.php?year=2008&type=
index.php?option=com_reservations&amp;task=askope&amp;nidser=2&amp;namser= “com_reservations”
index.php?option=com_reservations&task=askope&nidser=2&namser= “com_reservations”
intext:”Website by Mile High Creative”
inurl:”.php?author=”
inurl:”.php?cat=”
inurl:”.php?cmd=”
inurl:”.php?feedback=”
inurl:”.php?file=”
inurl:”.php?from=”
inurl:”.php?keyword=”
inurl:”.php?mail=”
inurl:”.php?max=”
inurl:”.php?pass=”
inurl:”.php?pass=”
inurl:”.php?q=”
inurl:”.php?query=”
inurl:”.php?search=”
inurl:”.php?searchstring=”
inurl:”.php?searchst­ring=”
inurl:”.php?tag=”
inurl:”.php?txt=”
inurl:”.php?vote=”
inurl:”.php?years=”
inurl:”.php?z=”
inurl:”contentPage.php?id=”
inurl:”displayResource.php?id=”
inurl:.com/search.asp
inurl:/poll/default.asp?catid=
inurl:/products/classified/headersearch.php?sid=
inurl:/products/orkutclone/scrapbook.php?id=
inurl:/search_results.php?search=
inurl:/­search_results.php?se­arch=
inurl:/search_results.php?search=Search&amp;k=
inurl:/search_results.php?search=Search&k=
inurl:”contentPage.php?id=”
inurl:”displayResource.php?id=”
inurl:com_feedpostold/feedpost.php?url=
inurl:headersearch.php?sid=
inurl:scrapbook.php?id=
inurl:search.php?q=
pages/match_report.php?mid= pages/match_report.php?mid=
```

#### Keywords to Find Admin Panels
Tips : 
1. Use these keywords to make Dorks.
2. Use these keywords with Burp Intruder or FFUF and wait for 200, 302 or 401 status code.
```code
login.html
login/
adm/
admin/
admin/account.html
admin/login.html
admin/login.htm
admin/controlpanel.html
admin/controlpanel.htm
admin/adminLogin.html
admin/adminLogin.htm
admin.htm
admin.html
adminitem/
adminitems/
administrator/
administration/
adminLogin/
admin_area/
manager/
letmein/
superuser/
access/
sysadm/
superman/
supervisor/
control/
member/
members/
user/
cp/
uvpanel/
manage/
management/
signin/
log-in/
log_in/
sign_in/
sign-in/
users/
accounts/
wp-login.php
bb-admin/admin.html
relogin.htm
relogin.html
registration/
moderator/
controlpanel/
fileadmin/
admin1.html
admin1.htm
admin2.html
yonetim.html
yonetici.html
phpmyadmin/
myadmin/
ur-admin/
Server/
wp-admin/
administr8/
webadmin/
administratie/
admins/
administrivia/
Database_Administration/
useradmin/
sysadmins/
admin1/
system-administration/
administrators/
pgadmin/
directadmin/
staradmin/
ServerAdministrator/
SysAdmin/
administer/
LiveUser_Admin/
sys-admin/
typo3/
panel/
cpanel/
cpanel_file/
platz_login/
rcLogin/
blogindex/
formslogin/
autologin/
support_login/
meta_login/
manuallogin/
simpleLogin/
loginflat/
utility_login/
showlogin/
memlogin/
login-redirect/
sub-login/
wp-login/
login1/
dir-login/
login_db/
xlogin/
smblogin/
customer_login/
UserLogin/
login-us/
acct_login/
bigadmin/
project-admins/
phppgadmin/
pureadmin/
sql-admin/
radmind/
openvpnadmin/
wizmysqladmin/
vadmind/
ezsqliteadmin/
hpwebjetadmin/
newsadmin/
adminpro/
Lotus_Domino_Admin/
bbadmin/
vmailadmin/
Indy_admin/
ccp14admin/
irc-macadmin/
banneradmin/
sshadmin/
phpldapadmin/
macadmin/
administratoraccounts/
admin4_account/
admin4_colon/
radmind-1/
Super-Admin/
AdminTools/
cmsadmin/
SysAdmin2/
globes_admin/
cadmins/
phpSQLiteAdmin/
navSiteAdmin/
server_admin_small/
logo_sysadmin/
power_user/
system_administration/
ss_vms_admin_sm/
bb-admin/
panel-administracion/
instadmin/
memberadmin/
administratorlogin/
pages/admin/<
admincp/
adminarea/
admincontrol/
modules/admin/
siteadmin/
adminsite/
kpanel/
vorod/
vorud/
adminpanel/
PSUser/
secure/
webmaster/
security/
usr/
root/
secret/
moderator.php
moderator.html
0admin/
0manager/
aadmin/
login_admin/
login_out/
loginerror/
loginok/
loginsave/
loginsuper/
logout/
secrets/
super1/
supervise/
admin1.php
admin1.html
admin2.php
admin2.html
yonetim.php
yonetim.html
yonetici.php
yonetici.html
admin/account.php
admin/account.html
admin/index.php
admin/index.html
admin/login.php
admin/login.html
admin/home.php
admin/controlpanel.html
admin/controlpanel.php
admin.php
admin.html
admin/cp.php
admin/cp.html
cp.php
cp.html
administrator/
administrator/index.html
administrator/index.php
administrator/login.html
administrator/login.php
administrator/account.html
administrator/account.php
administrator.php
administrator.html
login.html
modelsearch/login.php
moderator.php
moderator.html
moderator/login.php
moderator/login.html
moderator/admin.php
moderator/admin.html
account.php
account.html
controlpanel/
controlpanel.php
controlpanel.html
admincontrol.php
admincontrol.html
adminpanel.php
adminpanel.html
admin1.asp
admin2.asp
yonetim.asp
yonetici.asp
admin/account.asp
admin/index.asp
admin/login.asp
admin/home.asp
admin/controlpanel.asp
admin.asp
admin/cp.asp
cp.asp
administrator/index.asp
administrator/login.asp
administrator/account.asp
administrator.asp
login.asp
modelsearch/login.asp
moderator.asp
moderator/login.asp
moderator/admin.asp
account.asp
controlpanel.asp
admincontrol.asp
adminpanel.asp
fileadmin/
fileadmin.php
fileadmin.asp
fileadmin.html
administration/
administration.php
administration.html
sysadmin.php
sysadmin.html
phpmyadmin/
myadmin/
sysadmin.asp
sysadmin/
ur-admin.asp
ur-admin.php
ur-admin.html
ur-admin/
Server.php
Server.html
Server.asp
Server/
wp-admin/
administr8.php
administr8.html
administr8/
administr8.asp
webadmin/
webadmin.php
webadmin.asp
webadmin.html
administratie/
admins/
admins.php
admins.asp
admins.html
administrivia/
Database_Administration/
WebAdmin/
useradmin/
sysadmins/
admin1/
system-administration/
administrators/
pgadmin/
directadmin/
staradmin/
ServerAdministrator/
SysAdmin/
administer/
LiveUser_Admin/
sys-admin/
typo3/
panel/
cpanel/
cPanel/
cpanel_file/
platz_login/
rcLogin/
blogindex/
formslogin/
autologin/
support_login/
meta_login/
manuallogin/
simpleLogin/
loginflat/
utility_login/
showlogin/
memlogin/
members/
login-redirect/
sub-login/
wp-login/
login1/
dir-login/
login_db/
xlogin/
smblogin/
customer_login/
UserLogin/
login-us/
acct_login/
admin_area/
bigadmin/
project-admins/
phppgadmin/
pureadmin/
sql-admin/
openvpnadmin/
wizmysqladmin/
vadmind/
ezsqliteadmin/
hpwebjetadmin/
newsadmin/
adminpro/
Lotus_Domino_Admin/
bbadmin/
vmailadmin/
ccp14admin/
irc-macadmin/
banneradmin/
sshadmin/
phpldapadmin/
macadmin/
administratoraccounts/
admin4_account/
admin4_colon/
radmind-1/
Super-Admin/
AdminTools/
cmsadmin/
phpSQLiteAdmin/
server_admin_small
database_administration
system_administration
```
