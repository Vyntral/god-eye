package scanner

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var TakeoverFingerprints = map[string]string{
	// GitHub
	"github.io":             "There isn't a GitHub Pages site here",
	"githubusercontent.com": "There isn't a GitHub Pages site here",
	// Heroku
	"herokuapp.com": "no-such-app.herokuapp.com",
	"herokussl.com": "no-such-app.herokuapp.com",
	// AWS
	"s3.amazonaws.com":     "NoSuchBucket",
	"s3-website":           "NoSuchBucket",
	"elasticbeanstalk.com": "NoSuchBucket",
	"cloudfront.net":       "Bad Request",
	"elb.amazonaws.com":    "NXDOMAIN",
	// Azure
	"azurewebsites.net":     "404 Web Site not found",
	"cloudapp.net":          "404 Web Site not found",
	"cloudapp.azure.com":    "404 Web Site not found",
	"azurefd.net":           "404 Web Site not found",
	"blob.core.windows.net": "BlobNotFound",
	"azure-api.net":         "404 Resource not found",
	"azurehdinsight.net":    "404",
	"azureedge.net":         "404 Web Site not found",
	"trafficmanager.net":    "404 Web Site not found",
	// Google Cloud
	"appspot.com":            "Error: Not Found",
	"storage.googleapis.com": "NoSuchBucket",
	"googleplex.com":         "404. That's an error",
	// Shopify
	"myshopify.com": "Sorry, this shop is currently unavailable",
	// Pantheon
	"pantheonsite.io": "404 error unknown site",
	// Zendesk
	"zendesk.com": "Help Center Closed",
	// Various services
	"teamwork.com":        "Oops - We didn't find your site",
	"helpjuice.com":       "We could not find what you're looking for",
	"helpscoutdocs.com":   "No settings were found for this company",
	"ghost.io":            "The thing you were looking for is no longer here",
	"surge.sh":            "project not found",
	"bitbucket.io":        "Repository not found",
	"wordpress.com":       "Do you want to register",
	"smartling.com":       "Domain is not configured",
	"acquia.com":          "Web Site Not Found",
	"fastly.net":          "Fastly error: unknown domain",
	"uservoice.com":       "This UserVoice subdomain is currently available",
	"unbounce.com":        "The requested URL was not found on this server",
	"thinkific.com":       "You may have mistyped the address",
	"tilda.cc":            "Please renew your subscription",
	"mashery.com":         "Unrecognized domain",
	"intercom.help":       "This page is reserved for",
	"webflow.io":          "The page you are looking for doesn't exist",
	"wishpond.com":        "https://www.wishpond.com/404",
	"aftership.com":       "Oops.</h2><p>The page you're looking for doesn't exist",
	"aha.io":              "There is no portal here",
	"tictail.com":         "to target URL: <a href=\"https://tictail.com",
	"campaignmonitor.com": "Trying to access your account?",
	"cargocollective.com": "404 Not Found",
	"statuspage.io":       "You are being <a href=\"https://www.statuspage.io\">",
	"tumblr.com":          "There's nothing here.",
	"worksites.net":       "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
	"smugmug.com":         "class=\"message-text\">Page Not Found<",
	// Additional services
	"netlify.app":       "Not Found",
	"netlify.com":       "Not Found",
	"vercel.app":        "NOT_FOUND",
	"now.sh":            "NOT_FOUND",
	"fly.dev":           "404 Not Found",
	"render.com":        "NOT_FOUND",
	"gitbook.io":        "Domain not found",
	"readme.io":         "Project doesnt exist",
	"desk.com":          "Sorry, We Couldn't Find That Page",
	"freshdesk.com":     "There is no helpdesk here",
	"tave.com":          "Sorry, this profile doesn't exist",
	"feedpress.me":      "The feed has not been found",
	"launchrock.com":    "It looks like you may have taken a wrong turn",
	"pingdom.com":       "This public status page",
	"surveygizmo.com":   "data-html-name",
	"tribepad.com":      "Sorry, we could not find that page",
	"uptimerobot.com":   "This public status page",
	"wufoo.com":         "Profile not found",
	"brightcove.com":    "Error - Loss of soul",
	"bigcartel.com":     "Oops! We couldn't find that page",
	"activehosted.com":  "alt=\"LIGHTTPD - fly light.\"",
	"createsend.com":    "Double check the URL",
	"flexbe.com":        "Domain doesn't exist",
	"agilecrm.com":      "Sorry, this page is no longer available",
	"anima.io":          "not found",
	"proposify.com":     "If you need immediate assistance",
	"simplebooklet.com": "We can't find this FlipBook",
	"getresponse.com":   "With GetResponse Landing Pages",
	"vend.com":          "Looks like you've traveled too far",
	"strikingly.com":    "But if you're looking to build your own website",
	"airee.ru":          "Ошибка 402. Сервис",
	"anweb.ru":          "Эта страница не существует",
	"domain.ru":         "К сожалению, не удалось",
	"instapage.com":     "Looks Like You're Lost",
	"landingi.com":      "Nie znaleziono strony",
	"leadpages.net":     "Oops - We Couldn't Find Your Page",
	"pagewiz.com":       "PAGE NOT FOUND",
	"short.io":          "Link does not exist",
	"smartjobboard.com": "Company Not Found",
	"uberflip.com":      "Non-hub polygon  detected",
	"vingle.net":        "해당 페이지가 존재하지 않습니다",
	"ngrok.io":          "Tunnel",
	"kinsta.cloud":      "No Site For Domain",
	"canny.io":          "There is no such company",
	"hatena.ne.jp":      "404 Blog is not found",
	"medium.com":        "This page doesn't exist",
	"hatenablog.com":    "404 Blog is not found",
	"jetbrains.com":     "is not a registered InCloud YouTrack",
}

func CheckTakeover(subdomain string, timeout int) string {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Check CNAME
	c := dns.Client{Timeout: 3 * time.Second}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)

	r, _, err := c.Exchange(&m, "8.8.8.8:53")
	if err != nil || r == nil {
		return ""
	}

	var cname string
	for _, ans := range r.Answer {
		if cn, ok := ans.(*dns.CNAME); ok {
			cname = cn.Target
			break
		}
	}

	if cname == "" {
		return ""
	}

	// Check if CNAME matches any vulnerable service
	for service, fingerprint := range TakeoverFingerprints {
		if strings.Contains(cname, service) {
			// Verify by checking response
			resp, err := client.Get(fmt.Sprintf("http://%s", subdomain))
			if err != nil {
				resp, err = client.Get(fmt.Sprintf("https://%s", subdomain))
			}

			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 100000))
				if strings.Contains(string(body), fingerprint) {
					return service
				}
			}

			// If can't reach, might still be vulnerable
			if err != nil {
				return service + " (unverified)"
			}
		}
	}

	return ""
}

// Helper functions for connection pooling

func CheckRobotsTxtWithClient(subdomain string, client *http.Client) bool {
	urls := []string{
		fmt.Sprintf("https://%s/robots.txt", subdomain),
		fmt.Sprintf("http://%s/robots.txt", subdomain),
	}

	for _, url := range urls {
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

func CheckSitemapXmlWithClient(subdomain string, client *http.Client) bool {
	urls := []string{
		fmt.Sprintf("https://%s/sitemap.xml", subdomain),
		fmt.Sprintf("http://%s/sitemap.xml", subdomain),
	}

	for _, url := range urls {
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return true
		}
	}

	return false
}

func GetFaviconHashWithClient(subdomain string, client *http.Client) string {
	urls := []string{
		fmt.Sprintf("https://%s/favicon.ico", subdomain),
		fmt.Sprintf("http://%s/favicon.ico", subdomain),
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 100000))
		if err != nil || len(body) == 0 {
			continue
		}

		hash := md5.Sum(body)
		return hex.EncodeToString(hash[:])
	}

	return ""
}
