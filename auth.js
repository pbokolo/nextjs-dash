import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';

// Define the User type
// In JavaScript, we typically use JSDoc for type hints or rely on comments for type definitions
/**
 * @typedef {Object} User
 * @property {string} id
 * @property {string} email
 * @property {string} password
 * @property {string} name
 */

// Fetch user by email
async function getUser(email) {
  try {
    const result = await sql`SELECT * FROM users WHERE email=${email}`;
    return result.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (!parsedCredentials.success) {
          return null;
        }

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
