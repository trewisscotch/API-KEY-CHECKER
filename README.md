## API-KEY-CHECKER
### AIO API-KEY CHECKER|AWS|Twilio|Mailgun

Here is a list of easy checks for API key validity just from your terminal.
I also made an AIO script for more automation u just slide your keys and choose the mode.

Table of Contents

* Algolia API key
* Asana Access token
* AWS Access Key ID and Secret
* Bit.ly Access token
* Branch.io Key and Secret
* BrowserStack Access Key
* Buildkite Access token
* CircleCI Access Token
* DataDog API key
* Deviant Art Access Token
* Deviant Art Secret
* Dropbox API
* Facebook Access Token
* Facebook AppSecret
* Firebase
* FreshDesk API Key
* Github client id and client secret
* GitHub private SSH key
* Github Token
* Gitlab personal access token
* Firebase Cloud Messaging (FCM)
* Google Maps API key
* Google Recaptcha key
* Google Cloud Service Account credentials
* Heroku API key
* HubSpot API key
* Instagram Basic Display API
* Instagram Graph API
* Ipstack API Key
* JumpCloud API key
* Loqate API Key
* MailChimp API Key
* MailGun Private Key
* Mapbox API key
* Microsoft Azure Tenant
* Microsoft Shared Access Signatures (SAS)
* NPM token
* Pagerduty API token
* Paypal client id and secret key
* Pendo Integration Key
* Razorpay API key and secret key
* Salesforce API key
* SauceLabs Username and access Key
* SendGrid API Token
* Slack API token
* Slack Webhook
* Spotify Access Token
* Square
* Stripe Live Token
* Travis CI API token
* Twilio Account_sid and Auth token
* Twitter API Secret
* Twitter Bearer token
* WakaTime API Key
* WPEngine API Key
* Zapier Webhook Token
* Zendesk Access token

### Slack Webhook
If the below command returns missing_text_or_fallback_or_attachments, it means that the URL is valid, any other responses would mean that the URL is invalid.
``curl -s -X POST -H "Content-type: application/json" -d '{"text":""}' "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"``
### Slack API token
``curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN_HERE&pretty=1"``
### SauceLabs Username and access Key
``curl -u USERNAME:ACCESS_KEY https://saucelabs.com/rest/v1/users/USERNAME``
### Facebook AppSecret
You can generate access tokens by visiting the URL below.
``https://graph.facebook.com/oauth/access_token?client_id=ID_HERE&client_secret=SECRET_HERE&redirect_uri=&grant_type=client_credentials``
### Facebook Access Token
``https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2``
### Firebase
Requires a custom token, and an API key.
Obtain ID token and refresh token from custom token and API key: 
``curl -s -XPOST -H 'content-type: application/json' -d '{"token":":custom_token","returnSecureToken":True}' 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=:api_key'``
``Exchange ID token for auth token: curl -s -XPOST -H 'content-type: application/json' -d '{"idToken":":id_token"}' https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=:api_key'``
### Github Token
``curl -s -u "user:apikey" https://api.github.com/user
curl -s -H "Authorization: token TOKEN_HERE" "https://api.github.com/users/USERNAME_HERE/orgs"``
### Check scope of your api token
``curl "https://api.github.com/rate_limit" -i -u "user:apikey" | grep "X-OAuth-Scopes:"``
### Github client id and client secret
```curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'```
### Firebase Cloud Messaging
Reference: https://abss.me/posts/fcm-takeover
``curl -s -X POST --header "Authorization: key=AI..." --header "Content-Type:application/json" 'https://fcm.googleapis.com/fcm/send' -d '{"registration_ids":["1"]}'``
### GitHub private SSH key
SSH private keys can be tested against github.com to see if they are registered against an existing user account. If the key exists the username corresponding to the key will be provided. (source)
``$ ssh -i <path to SSH private key> -T git@github.com
Hi <username>! You've successfully authenticated, but GitHub does not provide shell access.``
### Twilio Account_sid and Auth token
``curl -X GET 'https://api.twilio.com/2010-04-01/Accounts.json' -u ACCOUNT_SID:AUTH_TOKEN``
### Twitter API Secret
``curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'``]
### Twitter Bearer token
``curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'``
### HubSpot API key
Get all owners:
``https://api.hubapi.com/owners/v2/owners?hapikey={keyhere}``
Get all contact details:
``https://api.hubapi.com/contacts/v1/lists/all/contacts/all?hapikey={keyhere}``
### Deviant Art Secret
``curl https://www.deviantart.com/oauth2/token -d grant_type=client_credentials -d client_id=ID_HERE -d client_secret=mysecret``
### Deviant Art Access Token
``curl https://www.deviantart.com/api/v1/oauth2/placebo -d access_token=Alph4num3r1ct0k3nv4lu3``
### Pendo Integration Key
``curl -X GET https://app.pendo.io/api/v1/feature -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'
curl -X GET https://app.pendo.io/api/v1/metadata/schema/account -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'``
### SendGrid API Token'
``curl -X "GET" "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer SENDGRID_TOKEN-HERE" -H "Content-Type: application/json"``
### Square
Detection:
App id/client secret: sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43} Auth token: EAAA[a-zA-Z0-9]{60}
Test App id & client secret:
``curl "https://squareup.com/oauth2/revoke" -d '{"access_token":"[RANDOM_STRING]","client_id":"[APP_ID]"}'  -H "Content-Type: application/json" -H "Authorization: Client [CLIENT_SECRET]"``
Response indicating valid credentials:
``empty``
Response indicating invalid credentials:
``{
  "message": "Not Authorized",
  "type": "service.not_authorized"
}``
Test Auth token:
``curl https://connect.squareup.com/v2/locations -H "Authorization: Bearer [AUHT_TOKEN]"``
Response indicating valid credentials:
``{"locations":[{"id":"CBASELqoYPXr7RtT-9BRMlxGpfcgAQ","name":"Coffee \u0026 Toffee SF","address":{"address_line_1":"1455 Market Street","locality":"San Francisco","administrative_district_level_1":"CA","postal_code":"94103","country":"US"},"timezone":"America/Los_Angeles"........``
Response indicating invalid credentials:
``{"errors":[{"category":"AUTHENTICATION_ERROR","code":"UNAUTHORIZED","detail":"This request could not be authorized."}]}``
### Dropbox API
``curl -X POST https://api.dropboxapi.com/2/users/get_current_account --header "Authorization: Bearer TOKEN_HERE"``
### AWS Access Key ID and Secret
Install awscli, set the access key and secret to environment variables, and execute the following command:
``AWS_ACCESS_KEY_ID=xxxx AWS_SECRET_ACCESS_KEY=yyyy aws sts get-caller-identity``
AWS credentials’ permissions can be determined using Enumerate-IAM. This gives broader view of the discovered AWS credentials privileges instead of just checking S3 buckets.
``git clone https://github.com/andresriancho/enumerate-iam
cd  enumerate-iam
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...``
### MailGun Private Key
``curl --user 'api:key-PRIVATEKEYHERE' "https://api.mailgun.net/v3/domains"``
### FreshDesk API Key
``curl -v -u user@yourcompany.com:test -X GET 'https://domain.freshdesk.com/api/v2/groups/1'
This requires the API key in 'user@yourcompany.com', pass in 'test' and 'domain.freshdesk.com' to be the instance url of the target. In case you get a 403, try the endpoint api/v2/tickets, which is accessible for all keys.``
### JumpCloud API Key
``List systems:curl -H "x-api-key: APIKEYHERE" "https://console.jumpcloud.com/api/systems"``
### Microsoft Azure Tenant
Format:
``CLIENT_ID: [0-9a-z\-]{36}
CLIENT_SECRET: [0-9A-Za-z\+\=]{40,50}
TENANT_ID: [0-9a-z\-]{36}``
Verification:
``curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'client_id=<CLIENT_ID>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=<CLIENT_SECRET>&grant_type=client_credentials' 'https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token'``
### Microsoft Shared Access Signatures (SAS)
The following powershell can be used to test a Shared Access Signature Token:

``static void UseAccountSAS(string sasToken)
{
    // Create new storage credentials using the SAS token.
    StorageCredentials accountSAS = new StorageCredentials(sasToken);
    // Use these credentials and the account name to create a Blob service client.
    CloudStorageAccount accountWithSAS = new CloudStorageAccount(accountSAS, "account-name", endpointSuffix: null, useHttps: true);
    CloudBlobClient blobClientWithSAS = accountWithSAS.CreateCloudBlobClient();
    // Now set the service properties for the Blob client created with the SAS.
    blobClientWithSAS.SetServiceProperties(new ServiceProperties()
    {
        HourMetrics = new MetricsProperties()
        {
            MetricsLevel = MetricsLevel.ServiceAndApi,
            RetentionDays = 7,
            Version = "1.0"
        },
        MinuteMetrics = new MetricsProperties()
        {
            MetricsLevel = MetricsLevel.ServiceAndApi,
            RetentionDays = 7,
            Version = "1.0"
        },
        Logging = new LoggingProperties()
        {
            LoggingOperations = LoggingOperations.All,
            RetentionDays = 14,
            Version = "1.0"
        }
    });
    // The permissions granted by the account SAS also permit you to retrieve service properties.
    ServiceProperties serviceProperties = blobClientWithSAS.GetServiceProperties();
    Console.WriteLine(serviceProperties.HourMetrics.MetricsLevel);
    Console.WriteLine(serviceProperties.HourMetrics.RetentionDays);
    Console.WriteLine(serviceProperties.HourMetrics.Version);
}``
### Heroku API key
Mapbox secret keys start with sk, rest start with pk (public token), sk (secret token), or tk (temporary token).
``curl "https://api.mapbox.com/geocoding/v5/mapbox.places/Los%20Angeles.json?access_token=ACCESS_TOKEN"``
### Salesforce API key
``curl https://instance_name.salesforce.com/services/data/v20.0/ -H 'Authorization: Bearer access_token_here'``
### Algolia API key
Be cautious when running this command, since the payload might execute within an administrative environment, depending on what index you are editing the highlightPreTag of. It's recommended to use a more silent payload (such as XSS Hunter) to prove the possible cross-site scripting attack.
``curl --request PUT \
  --url https://<application-id>-1.algolianet.com/1/indexes/<example-index>/settings \
  --header 'content-type: application/json' \
  --header 'x-algolia-api-key: <example-key>' \
  --header 'x-algolia-application-id: <example-application-id>' \
  --data '{"highlightPreTag": "<script>alert(1);</script>"}'``
  ### Zapier Webhook Token
``curl -H "Accept: application/json" -H "Content-Type: application/json" -X POST -d '{"name":"streaak"}' "webhook_url_here"``
### Pagerduty API token
``curl -H "Accept: application/vnd.pagerduty+json;version=2"  -H "Authorization: Token token=TOKEN_HERE" -X GET  "https://api.pagerduty.com/schedules"``
### BrowserStack Access Key
``curl -u "USERNAME:ACCESS_KEY" https://api.browserstack.com/automate/plan.json``
### Google Maps API key
Key restrictions are set per service. When testing the key, if the key is restricted/inactive on one service try it with another.
NameEndpointPricingStatic Mapshttps://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=KEY_HERE$2Streetviewhttps://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=KEY_HERE$7Embedhttps://www.google.com/maps/embed/v1/place?q=place_id:ChIJyX7muQw8tokR2Vf5WBBk1iQ&key=KEY_HEREVariesDirectionshttps://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=KEY_HERE$5Geocodinghttps://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=KEY_HERE$5Distance Matrixhttps://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=KEY_HERE$5Find Place from Texthttps://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key=KEY_HEREVariesAutocompletehttps://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=KEY_HEREVariesElevationhttps://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=KEY_HERE$5Timezonehttps://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=KEY_HERE$5Roadshttps://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=KEY_HERE$10Geolocatehttps://www.googleapis.com/geolocation/v1/geolocate?key=KEY_HERE$5
*Pricing is in USD per 1000 requests (for the first 100k requests)
More Information available here-
https://medium.com/@ozguralp/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e
https://github.com/ozguralp/gmapsapiscanner/
https://developers.google.com/maps/api-key-best-practices
### Google Recaptcha key
Send a POST to the following URL:
``https://www.google.com/recaptcha/api/siteverify``
secret and response are two required POST parameters, where secret is the key and response is the response to test for.
Regular expression: ^6[0-9a-zA-Z_-]{39}$. The API key always starts with a 6 and is 40 chars long. Read more here: https://developers.google.com/recaptcha/docs/verify.
### Google Cloud Service Account credentials
Service Account credentials may be found in a JSON file like this:
``$ cat service_account.json
{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n",
  "client_email": "...",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}``

If this is your case you may check these credentials using gcloud tool (how to install gcloud):
``$ gcloud auth activate-service-account --key-file=service_account.json
Activated service account credentials for: [...]
$ gcloud auth print-access-token
ya29.c...``
In case of success you’ll see access token printed in terminal. Please note that after verifying that credentials are actually valid you may want to enumerate permissions of these credentials which is another story.
### Branch.IO Key and Secret
Visit the following URL to check for validity:
``https://api-ssl.bitly.com/v3/shorten?access_token=ACCESS_TOKEN&longUrl=https://www.google.com``
### Buildkite Access token
``curl -H "Authorization: Bearer ACCESS_TOKEN" \
https://api.buildkite.com/v2/user``
### Asana Access token
``curl -H "Authorization: Bearer ACCESS_TOKEN" https://app.asana.com/api/1.0/users/me``
### Zendesk Access token
``curl https://{subdomain}.zendesk.com/api/v2/tickets.json \
  -H "Authorization: Bearer ACCESS_TOKEN"``
### MailChimp API Key
``curl --request GET --url 'https://<dc>.api.mailchimp.com/3.0/' --user 'anystring:<API_KEY>' --include``
### WPEngine API Key
This issue can be further exploited by checking out @hateshape’s gist https://gist.github.com/hateshape/2e671ea71d7c243fac7ebf51fb738f0a.
``curl "https://api.wpengine.com/1.2/?method=site&account_name=ACCOUNT_NAME&wpe_apikey=WPENGINE_APIKEY"``
### DataDog API key
``curl "https://api.datadoghq.com/api/v1/dashboard?api_key=<api_key>&application_key=<application_key>"``
### Travis CI API token
``curl -H "Travis-API-Version: 3" -H "Authorization: token <TOKEN>" https://api.travis-ci.com/user``
### WakaTime API Key
``curl "https://wakatime.com/api/v1/users/current/projects/?api_key=KEY_HERE"``
### Spotify Access Token
``curl -H "Authorization: Bearer <ACCESS_TOKEN>" https://api.spotify.com/v1/me``
### Instagram Basic Display API Access Token
E.g.: IGQVJ…
``curl -X GET 'https://graph.instagram.com/{user-id}?fields=id,username&access_token={access-token}'``
### Instagram Graph API Access Token
E.g.: EAAJjmJ…
``curl -i -X GET 'https://graph.facebook.com/v8.0/me/accounts?access_token={access-token}'``
### Gitlab personal access token
``curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"``
### Paypal client id and secret key
``curl -v https://api.sandbox.paypal.com/v1/oauth2/token \
   -H "Accept: application/json" \
   -H "Accept-Language: en_US" \
   -u "client_id:secret" \
   -d "grant_type=client_credentials"``
   The access token can be further used to extract data from the PayPal API. More information: https://developer.paypal.com/docs/api/overview/#make-rest-api-calls.
This can be verified using:
``curl -v -X GET "https://api.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1" -H "Content-Type: application/json" -H "Authorization: Bearer [ACCESS_TOKEN]"``
### Stripe Live Token
``curl https://api.stripe.com/v1/charges -u token_here:``
Keep the colon at the end of the token to prevent cURL from requesting a password.
The token is always in the following format: sk_live_24charshere, where the 24charshere part contains 24 characters from a-z A-Z 0-9. There is also a test key, which starts with sk_test, but this key is worthless since it is only used for testing purposes and most likely doesn't contain any sensitive information. The live key, on the other hand, can be used to extract/retrieve a lot of info — ranging from charges to the complete product list.
Keep in mind that you will never be able to get the full credit card information since Stripe only gives you the last 4 digits.
More info/complete documentation: https://stripe.com/docs/api/authentication.
### Razorpay API key and Secret key
This can be verified using:
``curl -u <YOUR_KEY_ID>:<YOUR_KEY_SECRET> \https://api.razorpay.com/v1/payments``
### CircleCI Access Token
``curl https://circleci.com/api/v1.1/me?circle-token=<TOKEN>``
### Loqate API key
``curl 'http://api.addressy.com/Capture/Interactive/Find/v1.00/json3.ws?Key=<KEY_HERE>&Countries=US,CA&Language=en&Limit=5&Text=BHAR'``
### Ipstack API Key
``curl 'https://api.ipstack.com/{ip_address}?access_key={keyhere}'``
### NPM token
You can verify NPM token using npm (replacing 00000000-0000-0000-0000-000000000000 with NPM token):
``export NPM_TOKEN="00000000-0000-0000-0000-000000000000"
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
npm whoami``
Another way to verify token is to query API directly:
``curl -H 'authorization: Bearer 00000000-0000-0000-0000-000000000000' 'https://registry.npmjs.org/-/whoami'``

You’ll get username in response in case of success, 401 Unauthorized in case if token doesn't exists and 403 Forbidden in case if your IP address is not whitelisted.
NPM token can be CIDR-whitelisted. Thus if you are using token from non-whitelisted CIDR you’ll get 403 Forbidden in response. So try to verify NPM token from different IP ranges!.
P.S. Some companies uses registries other than registry.npmjs.org. If it's the case replace all registry.npmjs.org occurrences with domain name of company's NPM registry.














