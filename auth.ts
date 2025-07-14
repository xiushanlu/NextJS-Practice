import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';
 
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });
 
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}
 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);

        if (!parsedCredentials.success) {
            console.log('invalid input format', credentials);
            return null;
        }

        const { email, password } = parsedCredentials.data;
        console.log('trying login for email:', email);

        const user = await getUser(email);
        if (!user) {
            console.log('no user found for email:', email);
            return null;
        }
        console.log('user found:', user);

        const passwordsMatch = await bcrypt.compare(password, user.password);
        console.log('passwords match:', passwordsMatch);

        if (passwordsMatch) return user;

        console.log('password incorrect:', password);
        return null;
        }
    }),
  ],
});