## `Components of OAuth2`

1. `Resource Server`
   1. The main application
2. `User (Resource Owner)`
3. `Client`
   - The client application
   - Has client ID and secret
     - This is not the user creds!
4. `Authentication Server`

## `Grants`

- way of obtaining a token

Common Grants:

1. Authorization Code
2. Password
3. Refresh Token
4. Client Credentials

```mermaid
%%{
  init: {
    "sequence": {
      "showSequenceNumbers": "true",
      "wrap": "true"
    }
  }
}%%
sequenceDiagram

  User->>Client: I want to access my account
  Client->>User: Tell the Authorization Server
  User->>Auth Server: I allow the client to access my accounts,<br/> these are my creds to prove it
  Auth Server->>Client: User allowed you to access <br/> her accounts
  Client->>Auth Server: Give me the user tokens
  Auth Server->>Client: Here is a token
  Client->>Resource Server: I want to access this user account. <br/> Here is a token from Auth Server
  Resource Server->>Client: Here is the resource requested


```

`Step 3.`

- user directly communicates to the Authentication server
- User dont send the credentials to the client app
- Technically, what happens is that when the client redirects the user to the Auth Server <br /> The client calls the Auth Server with the ff request details:
  - `response_type` - with value `code`, tells the auth server that client expects a code
  - `client_id` - this identifies the client itself
  - `redirect_uri` - tells the authserver where to redirect the user after successfule authentication
    - Sometimes the auth server already knows a default redirect URI for eact client
      - for this reason, client doesnt need to send the redirect URI
  - `scope` - similar to granted authorities
  - `state` - which defines a cross-site request forgery (CSRF) token, used for CSRF protection
