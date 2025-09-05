;; JWT - A JSON Web Token (JWT) library for CHICKEN Scheme
;;
;; This library provides JWT creation and verification using the HS256 (HMAC-SHA256)
;; algorithm. It supports standard JWT claims validation including expiration (exp),
;; not-before (nbf), issued-at (iat), issuer (iss), and audience (aud) claims.
;;
;; Basic usage:
;;   (import jwt)
;;   
;;   ;; Create a JWT
;;   (define token (make-jwt-hs256 '((sub . "user123") (exp . 1640995200)) "secret"))
;;   
;;   ;; Decode a JWT (no validation)
;;   (define-values (header payload) (jwt-decode token))
;;   
;;   ;; Decode and verify a JWT
;;   (define-values (header payload) (jwt-validate-hs256 token "secret"))
;;
;; Copyright 2025 Rolando Abarca
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:
;;
;; 1. Redistributions of source code must retain the above copyright
;; notice, this list of conditions and the following disclaimer.
;;
;; 2. Redistributions in binary form must reproduce the above
;; copyright notice, this list of conditions and the following
;; disclaimer in the documentation and/or other materials provided
;; with the distribution.
;;
;; 3. Neither the name of the copyright holder nor the names of its
;; contributors may be used to endorse or promote products derived
;; from this software without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;; “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
;; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
;; COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
;; INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;; SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;; STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
;; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
;; OF THE POSSIBILITY OF SUCH DAMAGE.

(module jwt
 (make-jwt-hs256 jwt-decode jwt-validate-hs256)

 (import
  scheme
  chicken.base
  chicken.blob
  chicken.time
  chicken.string
  medea
  base64.urlsafe
  openssl.hmac)

 (define (now-seconds) (inexact->exact (round (current-seconds))))


 ;; make-jwt-hs256: Creates a JWT token using HMAC-SHA256 signing
 ;;
 ;; Parameters:
 ;;   payload - An association list representing the JWT payload/claims
 ;;   secret  - The signing secret (string or blob)
 ;;   extra-header - Optional additional header fields (default: '())
 ;;
 ;; Returns: A JWT token string
 ;;
 ;; Example:
 ;;   (make-jwt-hs256 '((sub . "user123")
 ;;                     (exp . 1640995200)
 ;;                     (name . "John Doe"))
 ;;                   "my-secret-key")
 ;;
 ;;   With custom header:
 ;;   (make-jwt-hs256 '((sub . "user123"))
 ;;                   "secret"
 ;;                   extra-header: '((kid . "key1")))
 (define (make-jwt-hs256 payload secret
                         #!key (extra-header '()))
   (let* ((header (append `((alg . "HS256") (typ . "JWT")) extra-header))
          (h-json (json->string header))
          (p-json (json->string payload))
          (h64 (base64-encode-urlsafe h-json))
          (p64 (base64-encode-urlsafe p-json))
          (signing-input (string-append h64 "." p64))
          (sig-bytes (hmac-sha256
                      (if (string? secret) (string->blob secret) secret)
                      (string->blob signing-input)))
          (s64 (base64-encode-urlsafe (blob->string sig-bytes))))
     (string-append h64 "." p64 "." s64)))

;; jwt-decode: Decodes a JWT token without any validation
;;
;; Parameters:
;;   token - The JWT token string to decode
;;
;; Returns: (values header payload) - Returns both header and payload as alists
;;
;; Raises: (error ...) only on malformed token structure
;;
;; Note: This function does NOT verify the signature or validate claims.
;;       Use jwt-validate for secure token verification.
;;
;; Example:
;;   (define-values (header payload) (jwt-decode token))
(define (jwt-decode token)
  (let* ((parts (string-split token "."))
         (_ (when (not (= (length parts) 3))
              (error "malformed token: expected 3 segments")))
         (h64 (list-ref parts 0))
         (p64 (list-ref parts 1))
         (h-json  (base64-decode-urlsafe h64))
         (p-json  (base64-decode-urlsafe p64))
         (header  (read-json h-json))
         (payload (read-json p-json)))
    (values header payload)))

 ;; JWT Validate (HS256)
 ;; 
 ;; jwt-validate-hs256: Decodes and verifies a JWT token using HMAC-SHA256
 ;;
 ;; Parameters:
 ;;   token        - The JWT token string to decode and verify
 ;;   secret       - The signing secret (string or blob) used to verify signature
 ;;   leeway       - Time leeway in seconds for claim validation (default: 60)
 ;;   expected-iss - Expected issuer claim value for validation (default: #f)
 ;;   expected-aud - Expected audience claim value for validation (default: #f)
 ;;
 ;; Returns: (values header payload) - Returns both header and payload as alists
 ;;
 ;; Raises: (error ...) on any validation failure including:
 ;;   - Malformed token structure
 ;;   - Invalid or missing algorithm
 ;;   - Signature verification failure
 ;;   - Token expiration (exp claim)
 ;;   - Token not yet valid (nbf claim)
 ;;   - Token issued in future (iat claim)
 ;;   - Issuer mismatch (iss claim)
 ;;   - Audience mismatch (aud claim)
 ;;
 ;; Example:
 ;;   (define-values (header payload) 
 ;;     (jwt-validate-hs256 "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." "secret"))
 ;;
 ;;   With validation parameters:
 ;;   (define-values (header payload)
 ;;     (jwt-validate-hs256 token "secret" 
 ;;                         leeway: 30
 ;;                         expected-iss: "my-app"
 ;;                         expected-aud: "api-users"))
 ;; -----------------------------------------------------------------------------
 (define (jwt-validate-hs256 token secret
                             #!key (leeway 60) (expected-iss #f) (expected-aud #f))
   ;; 1) decode token structure (reuse jwt-decode)
   (define-values (header payload) (jwt-decode token))
   
   ;; 2) get token parts for signature verification
   (let* ((parts (string-split token "."))
          (h64 (list-ref parts 0))
          (p64 (list-ref parts 1))
          (s64 (list-ref parts 2))
          (sig (string->blob (base64-decode-urlsafe s64))))
     ;; 3) alg guard
     (let ((alg (alist-ref 'alg header)))
       (when (not (and (string? alg) (string=? alg "HS256")))
         (error "disallowed or missing alg")))
     ;; 4) verify signature (over the two untouched base64url segments joined by '.')
     (let* ((signing-input (string-append h64 "." p64))
            (expected (hmac-sha256
                       (if (string? secret) (string->blob secret) secret)
                       (string->blob signing-input))))
       (when (not (blob=? expected sig))
         (error "signature verification failed")))
     ;; 5) claim checks
     (let* ((now (now-seconds))
            (exp (alist-ref 'exp payload))
            (nbf (alist-ref 'nbf payload))
            (iat (alist-ref 'iat payload))
            (iss (alist-ref 'iss payload))
            (aud (alist-ref 'aud payload)))
       (when (and (integer? exp) (> (+ now leeway) exp)) (error "token expired"))
       (when (and (integer? nbf) (< (- now leeway) nbf)) (error "token not yet valid"))
       (when (and (integer? iat) (> (- iat leeway) now)) (error "issued in the future"))
       (when (and expected-iss (or (not (string? iss)) (not (string=? iss expected-iss))))
         (error "issuer mismatch"))
       (when (and expected-aud
                  (not (or (and (string? aud) (string=? aud expected-aud))
                           (and (vector? aud)
				(let loop ((i 0))
                                  (and (< i (vector-length aud))
                                       (or (and (string? (vector-ref aud i))
						(string=? (vector-ref aud i) expected-aud))
                                           (loop (+ i 1)))))))))
         (error "audience mismatch")))
     (values header payload)))

;; -----------------------------------------------------------------------------
;; Usage Examples
;; -----------------------------------------------------------------------------

;; Example 1: Basic JWT creation, decoding, and validation
;;
;;   (import jwt)
;;   (import chicken.time)
;;   
;;   ;; Create a simple JWT with expiration
;;   (define payload `((sub . "user123")
;;                     (name . "John Doe")  
;;                     (exp . ,(+ (inexact->exact (current-seconds)) 3600)))) ; expires in 1 hour
;;   
;;   (define token (make-jwt-hs256 payload "my-secret-key"))
;;   (print "Generated token: " token)
;;   
;;   ;; Decode without validation (unsafe - for inspection only)
;;   (define-values (header payload-unsafe) (jwt-decode token))
;;   (print "Header: " header)
;;   (print "Payload (unverified): " payload-unsafe)
;;   
;;   ;; Decode and verify the token (safe)
;;   (define-values (header-verified payload-verified)
;;     (jwt-validate-hs256 token "my-secret-key"))
;;   
;;   (print "Verified Header: " header-verified)
;;   (print "Verified Payload: " payload-verified)

;; Example 2: JWT with additional claims and validation
;;
;;   (import jwt)
;;   (import chicken.time)
;;   
;;   (define now (inexact->exact (current-seconds)))
;;   (define payload `((sub . "api-user")
;;                     (iss . "my-app")
;;                     (aud . "api-service")
;;                     (iat . ,now)
;;                     (exp . ,(+ now 1800))  ; expires in 30 minutes
;;                     (nbf . ,now)           ; valid from now
;;                     (roles . #("admin" "user"))))
;;   
;;   ;; Create JWT with custom header
;;   (define token (make-jwt-hs256 payload "super-secret"
;;                                extra-header: '((kid . "key-2025"))))
;;   
;;   ;; Verify with strict validation
;;   (define-values (header payload-decoded)
;;     (jwt-validate-hs256 token "super-secret"
;;                         leeway: 10  ; allow 10 seconds clock skew
;;                         expected-iss: "my-app"
;;                         expected-aud: "api-service"))

;; Example 3: Error handling
;;
;;   (import jwt)
;;   
;;   ;; jwt-decode never fails (except for malformed tokens)
;;   (define-values (h p) (jwt-decode token))  ; Always works
;;   
;;   ;; jwt-validate-hs256 will fail with signature verification error
;;   (condition-case
;;     (jwt-validate-hs256 token "wrong-secret")
;;     ((exn) (print "JWT verification failed: " (condition-property-accessor 'exn 'message))))
;;   
;;   ;; This will fail with expired token error  
;;   (define expired-payload '((sub . "user") (exp . 1234567890)))  ; old timestamp
;;   (define expired-token (make-jwt-hs256 expired-payload "secret"))
;;   (condition-case
;;     (jwt-validate-hs256 expired-token "secret")
;;     ((exn) (print "Token expired: " (condition-property-accessor 'exn 'message))))

 )
