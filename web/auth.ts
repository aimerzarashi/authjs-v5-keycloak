import NextAuth from "next-auth";
import { AdapterSession } from "@auth/core/adapters";
import { Awaitable } from "@auth/core/types";
import Keycloak from "next-auth/providers/keycloak";
import { JWT } from "@auth/core/jwt";

type Account = {
  id_token: string;
  access_token: string;
  refresh_token: string;
  expires_at: number;
  refresh_expires_at: number;
};

declare module "@auth/core/types" {
  interface Session {
    account?: Account;
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    account?: Account;
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [Keycloak],
  session: {
    strategy: "jwt",
    updateAge: 5 * 60,
  },
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        return {
          ...token,
          account: {
            id_token: account.id_token ? account.id_token : "",
            access_token: account.access_token ? account.access_token : "",
            refresh_token: account.refresh_token ? account.refresh_token : "",
            expires_at: account.expires_at ? account.expires_at : 0,
            refresh_expires_at:
              account.expires_at &&
                account.expires_in &&
                account.refresh_expires_in
                ? account.expires_at -
                account.expires_in +
                (account.refresh_expires_in as number)
                : 0,
          },
        };
      }

      if (
        token.account?.expires_at &&
        Math.floor(Date.now() / 1000) < token.account?.expires_at
      ) {
        return token;
      }

      if (
        token.account?.refresh_expires_at &&
        Math.floor(Date.now() / 1000) < token.account?.refresh_expires_at
      ) {
        const response = await fetch(
          `${process.env.AUTH_KEYCLOAK_ISSUER}/protocol/openid-connect/token`,
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: process.env.AUTH_KEYCLOAK_ID!,
              client_secret: process.env.AUTH_KEYCLOAK_SECRET!,
              grant_type: "refresh_token",
              refresh_token: token.account?.refresh_token!,
            }),
            method: "POST",
          }
        );

        const tokens = await response.json();
        if (!response.ok) {
          return null;
        }

        return {
          ...token,
          account: {
            id_token: tokens.id_token,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Math.floor(Date.now() / 1000) + tokens.expires_in,
            refresh_expires_at:
              Math.floor(Date.now() / 1000) + tokens.refresh_expires_in,
          },
        };
      }

      if (
        token.account?.refresh_expires_at &&
        Math.floor(Date.now() / 1000) >= token.account?.refresh_expires_at
      ) {
        return null;
      }

      return token;
    },
    async session({ session, token }) {
      return {
        ...session,
        account: token.account,
      };
    },
  },
  events: {
    signOut: async (message:
      | { session: void | Awaitable<AdapterSession | null | undefined>; }
      | { token: Awaitable<JWT | null>; }) => {
      if ("token" in message && message.token) {
        const token = await message.token;
        const response = await fetch(
          `${process.env.AUTH_KEYCLOAK_ISSUER}/protocol/openid-connect/logout`,
          {
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: process.env.AUTH_KEYCLOAK_ID!,
              client_secret: process.env.AUTH_KEYCLOAK_SECRET!,
              grant_type: "refresh_token",
              refresh_token: token?.account?.refresh_token!,
            }),
            method: "POST",
          }
        );
      }
    },
  },
});
