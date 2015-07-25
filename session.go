package auth


import (
    "errors"
    "net/http"
    "fmt"
    "time"
    
    // We should vendor this dependency... or simply remove as it is likely very simple and we only need encryption
    "github.com/fragmenta/auth/internal/cookie"
)

// These should be set on app startup from ENV variables
// Should these be in the session store object, not out here as globals?
var HMACKey          []byte
var SecretKey        []byte
var SessionName      string
var SecureCookies    bool
var SessionUserKey   string


// Interface for a session store (backed by unknown storage)
type SessionStore interface {
    Get(string) string
    Set(string,string) 
    Load(request *http.Request) error
    Save(http.ResponseWriter) error
    Clear(http.ResponseWriter)
}


// Concrete version of SessionStore, which stores the information encrypted with bcrypt in cookies.
type CookieSessionStore struct {
    values  map[string]string
}


func init() {
    // HttpOnly is on by default
    SecureCookies       = false // off by default
    SessionName         = "fragmenta_session"
    SessionUserKey      = "user_id"
}


// Fetch or create the current session
func Session(writer http.ResponseWriter,request *http.Request) (SessionStore, error) {
    
    
    if len(HMACKey) == 0 || len(SecretKey) == 0 {
        return nil,errors.New("Authentication secrets not initialised")
    }
    
    // Return the current session store from cookie or a new one if none found
    s := &CookieSessionStore{
        values:make(map[string]string,0),
	}
    
    // Check if the session exists
    err := s.Load(request)
    if err != nil {
       // If no session, write it out for the first time (empty)
       fmt.Printf("Error on cookie load: %s\n",err)
       s.Save(writer)
       return s,nil
    }
    
    return s,nil
}


// Get a value from the session
func (s *CookieSessionStore) Get(key string) string {
   return s.values[key]
}

// Set a value in the session - NB you must call Save after this if you wish to save
func (s *CookieSessionStore) Set(key string,value string)  {
   s.values[key] = value 
}

func (s *CookieSessionStore) Load(request *http.Request) error {
    
    // Just replace this with your own methods on CookieSessionStore...
    cookieMonster := cookie.New(HMACKey,SecretKey)
  
    cookie, err := request.Cookie(SessionName)
    if err != nil {
        return err
    }
    
  //  fmt.Printf("Cookie load: %v\n%v\n",err,cookie)
    
    
    // Read the encrypted values back out into our values in the session
    err = cookieMonster.Decode(SessionName, cookie.Value, &s.values);
    if err != nil {
        return err
    }
    
    return nil
}


func (s *CookieSessionStore) Save(writer http.ResponseWriter) error {
  //  println("SAVING SESSION")
 
    
    // Just replace this with your own methods on CookieSessionStore...
    cookieMonster := cookie.New(HMACKey, SecretKey)
  

    encrypted, err := cookieMonster.Encode(SessionName, s.values)
    if err != nil {
        return err
    }
    
    cookie  := &http.Cookie{
    			Name:  SessionName,
    			Value: encrypted,
                HttpOnly: true,
                Secure: SecureCookies,
            	Path:  "/",
                Expires: time.Now().AddDate(0,0,7),// Expires in seven days
    		
    		 }
             
              
   http.SetCookie(writer,cookie)
	
   return nil
}

// THIS IS BROKEN - NOT CLEARING COOKIE PROPERLY - INVESTIGATE

// Clear the session values and save out
func (s *CookieSessionStore) Clear(writer http.ResponseWriter)  {
    cookie  := &http.Cookie{
    			Name:  SessionName,
    			Value: "",
                MaxAge: -1,
    			Path:  "/",
    		 }
          
   http.SetCookie(writer,cookie)
}

