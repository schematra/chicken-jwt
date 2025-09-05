(module jwt
 (make-jwt-hs256 jwt-decode-hs256)

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

 (define (assoc-any k al)
   (or (assoc k al)
      (and (symbol? k) (assoc (symbol->string k) al))
      (and (string? k) (assoc (string->symbol k) al))))

 (let* ((secret "thebigsecretthatsverylong")
	(payload `((sub . "123456")
		   (name . "Ada")
		   (iat . ,(now-seconds))
		   (exp . ,(+ (now-seconds) 3600))))
	(tok (make-jwt-hs256 payload secret)))
   (print tok))
 
 ;; -----------------------------------------------------------------------------
 ;; JWT Encode (HS256)
 ;; -----------------------------------------------------------------------------
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
          (s64 (b64url-encode-bytes sig-bytes)))
     (string-append h64 "." p64 "." s64)))

 ;; JWT Decode + Verify (HS256)
 ;;   - Returns (values header payload) on success
 ;;   - Raises (error ...) on failure
 ;; -----------------------------------------------------------------------------
 (define (jwt-decode-hs256 token secret
                           #!key (leeway 60) (expected-iss #f) (expected-aud #f))
   ;; 1) split
   (let* ((parts (string-split token "."))
          (_ (when (not (= (length parts) 3))
               (error "malformed token: expected 3 segments")))
          (h64 (list-ref parts 0))
          (p64 (list-ref parts 1))
          (s64 (list-ref parts 2))
          ;; 2) decode
          (h-json  (base64-decode-urlsafe h64))
          (p-json  (base64-decode-urlsafe p64))
          (sig     (base64-decode-urlsafe s64))
          (header  (read-json h-json))
          (payload (read-json p-json)))
     ;; 3) alg guard
     (let* ((a1 (assoc-any 'alg header))
            (alg (and a1 (cdr a1))))
       (when (not (and (string? alg) (string=? alg "HS256")))
         (error "disallowed or missing alg")))
     ;; 4) verify signature (over the two untouched base64url segments joined by '.')
     (let* ((signing-input (string-append h64 "." p64))
            (expected (hmac-sha256
                       (if (string? secret) (string->blob secret) secret)
                       (string->blob signing-input))))
       (display sig)
       (when (not (blob=? expected sig))
         (error "signature verification failed")))
     ;; 5) claim checks
     (let* ((now (now-seconds))
            (get (lambda (k) (let ((p (assoc-any k payload))) (and p (cdr p)))))
            (exp (get 'exp))
            (nbf (get 'nbf))
            (iat (get 'iat))
            (iss (get 'iss))
            (aud (get 'aud)))
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
 )
