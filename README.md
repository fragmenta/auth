# Package Auth
Package auth provides helpers for encryption, hashing and encoding.

### Usage

Setup the package on startup

```Go 
  auth.HMACKey = auth.HexToBytes("myhmac_key_from_config")
  auth.SecretKey = auth.HexToBytes("my_secret_key_from_config")
  auth.SessionName = "my_cookie_name"
  auth.SecureCookies = true
```

Use auth.HashPassword to encrypt and auth.CheckPassword to check hashed passwords (with bcrypt)

```Go 
  user.HashedPassword, err = auth.HashPassword(params.Get("password")
  if err != nil {
    return err
  }
  err = auth.CheckPassword(params.Get("password"), user.HashedPassword)
```

Use auth.Session to set and get values from cookies. 

```Go 
  // Build the session from the secure cookie, or create a new one
  session, err := auth.Session(writer, request)
  if err != nil {
    return err
  }
  
  // Store something in the session
  session.Set("my_key","my_value")
  session.Save(writer)
```

