import NextAuth from "next-auth"
import Keycloak from "next-auth/providers/keycloak"
import { JWT } from "next-auth/jwt"

type Account = {
  id_token: string
  access_token: string
  refresh_token: string
  expires_in: number
  refresh_expires_in: number
  expires_at: number
}

declare module "next-auth" {
  interface Session {
    account?: Account
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    account?: Account
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [Keycloak],
  session: {
    strategy: "jwt"
  },
  callbacks: {
    async jwt({ token, user, account, profile }) {
      console.debug({
        callbacks_jwt: {
          token: token,
          user: user,
          account: account,
          profile: profile,
        }
      });
      if (account) {
        return {
          ...token,
          account: {
            id_token: account.id_token ? account.id_token : "",
            access_token: account.access_token ? account.access_token : "",
            refresh_token: account.refresh_token ? account.refresh_token : "",
            expires_in: account.expires_in ? account.expires_in : 0,
            refresh_expires_in: account.refresh_expires_in as number ? account.refresh_expires_in as number : 0,
            expires_at: account.expires_at ? account.expires_at : 0,
          }
        }
      } else if (token.account?.expires_in && Date.now() < token.account?.expires_at) {
        return token
      } else if (token.account?.refresh_expires_in) {
        try {
          const response = await fetch(process.env.AUTH_KEYCLOAK_ISSUER!, {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: process.env.AUTH_KEYCLOAK_ID!,
              client_secret: process.env.AUTH_KEYCLOAK_SECRET!,
              grant_type: "refresh_token",
              refresh_token: token.account.refresh_token,
            }),
            method: "POST",
          })
          const tokens = await response.json()
          if (response.ok) {
            return {
              ...token,
              account: {
                id_token: tokens.id_token ? tokens.id_token : "",
                access_token: tokens.access_token ? tokens.access_token : "",
                refresh_token: tokens.refresh_token ? tokens.refresh_token : "",
                expires_in: tokens.expires_in ? tokens.expires_in : 0,
                refresh_expires_in: tokens.refresh_expires_in as number ? tokens.refresh_expires_in as number : 0,
                expires_at: tokens.expires_at ? tokens.expires_at : 0,
              }
            }
          }
        } catch (error) {
          console.error(error)
        }
      }
      return token
    },
    session({ session, token }) {
      console.debug({
        callbacks_session: {
          session,
          token
        }
      });
      return {
        ...session,
        account: token.account
      }
    },
  },
  events: {
    signOut: async (message) => {
      console.debug({
        events_signOut: {
          message
        }
      })
    }
  },
})