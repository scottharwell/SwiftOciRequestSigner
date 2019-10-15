# SwiftOciRequestSigner

This swift framework provides an easy-to-use singleton for Swift projects that need to generate a signing header for REST API requests to Oracle Cloud Infrastructure.

## Usage

Simply include the framework as a Swift package in Xcode 11 or later.

Assign the required OCI signature propertie as outlined below.

* Tenancy OCID
* User OCID
* Cert Fingerprint
* Private Key

```swift

// Assume 

OciRequestSigner.shared.tenancyId = self.tenancyOCID // assumes the tenancy id is assigned to the current class
OciRequestSigner.shared.userId = self.userOCID // assumes the user id is assigned to the current class
OciRequestSigner.shared.thumbprint = self.certFingerprint // assumes the cert fingerprint is assigned to the current class

do {
    // You can set the private key from a PEM file embedded in your project.
    try OciRequestSigner.shared.setKey(fileName: "pk", fileExtention: "pem", bundle: bundle)
    
    // Or you can set the private key from a PEM string
    let key = "MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQABAoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiAQWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOKkqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUgf1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogcmSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEAgIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmWG6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA=="
    try OciRequestSigner.shared.setKey(key: key)
} catch {
// Do something with the error.
}
```

Once the singleton is configured, then you just need to pass any given URLRequest that you want to make to an OCI API to the `sign` method.  It will be returned with the appropriate signature in the `Authorization` header.

Also, ensure that the appropriate headers are supplied as per the OCI Signature v1 spec; `POST` and `PATCH` require extra headers.  The headers `date` and `host` are automatically applied if you use the singleton's `getUrlRequest` method.  You can set the headers manually, if you need to.  Once your headers are configured, then run the `sign` method on the URLRequest.

```swift
func testPost(_ data: Data) {
    do {
        guard let url = URL(string: "https://iaas.us-phoenix-1.oraclecloud.com/20160918/volumeAttachments") else { throw Error }
        var postRequest = try OciRequestSigner.shared.getUrlRequest(url: url)
        postRequest.httpBody = data
        
        postRequest = try OciRequestSigner.shared.sign(postRequest)
        // Submit the postRequest
    } catch {
        // Do something with the error
    }
}
```
