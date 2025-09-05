(import test)
(import chicken.base chicken.blob chicken.time jwt)

(define jwt-str "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiQWRhIiwiaWF0IjoxNzU3MDI0NjI4LCJleHAiOjE3NTcwMjgyMjh9._CAn2khlBW_USU796ovDX-lQfV_NqxHyALwh0B9zdfM")
(define header '((alg . "HS256") (typ . "JWT")))
(define payload '((sub . "123456") (name . "Ada") (iat . 1757024628) (exp . 1757028228)))
(define secret "thebigsecretthatsverylong")

(define (now-seconds) (inexact->exact (round (current-seconds))))

(define (build-jwt payload secret #!optional (iat-delta 0) (exp-delta 3600))
  (let ((now (now-seconds)))
    (make-jwt-hs256 (append `((iat . ,(+ now iat-delta)) (exp . ,(+ now exp-delta))) payload) secret)))

(test-group
 "jwt"
 (test "creates a jwt"
       jwt-str
       (make-jwt-hs256 payload secret))
 (let-values (((header payload) (jwt-validate-hs256 (build-jwt payload secret 0 100) secret)))
   (test "correct decoded payload"
	 "Ada"
	 (alist-ref 'name payload))
   (test "correct decoded header"
	 "HS256"
	 (alist-ref 'alg header)))
 (test-error "error when the token has expired"
       (jwt-validate-hs256 (build-jwt payload secret 0 -100) secret))
 (test-error "error on malformed encoded token"
       (jwt-validate-hs256 "foo.bar" "secret"))
 (test-error "error on invalid data"
       (jwt-validate-hs256 "foo.bar.baz" "secret"))
 (test-error "error when signature check fails"
	     (jwt-validate-hs256 (build-jwt payload secret) "notthesecret"))
 
 ;; Test leeway functionality with corrected logic
 ;; For exp: token expired if exp < (now - leeway), so token expired 10s ago should pass with 20s leeway
 (test-assert "token expired within leeway should pass"
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (exp . ,(- now 10))) secret) secret leeway: 20)
         #t))
 (test-error "token expired outside leeway should fail"
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (exp . ,(- now 30))) secret) secret leeway: 20)))
 
 ;; Test nbf (not-before) claim with leeway  
 ;; For nbf: not valid if nbf > (now + leeway), so token valid in 10s should pass with 20s leeway
 (test-assert "token with nbf claim within leeway should pass"
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (nbf . ,(+ now 10))) secret) secret leeway: 20)
         #t))
 (test-error "token with nbf claim outside leeway should fail"  
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (nbf . ,(+ now 30))) secret) secret leeway: 20)))
 
 ;; Test iat (issued-at) claim with leeway
 ;; For iat: future if iat > (now + leeway), so token issued 10s in future should pass with 20s leeway
 (test-assert "token with future iat claim within leeway should pass"
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (iat . ,(+ now 10))) secret) secret leeway: 20)
         #t))
 (test-error "token with future iat claim outside leeway should fail"
       (let ((now (now-seconds)))
         (jwt-validate-hs256 (make-jwt-hs256 `((sub . "test") (iat . ,(+ now 30))) secret) secret leeway: 20)))
 )

(test-exit)
