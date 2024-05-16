// This expression is not callable.
//   Type 'typeof import("d:/Seneca/Winter Semester 7/PRJ666/Web-App-Repo/chronicle-web-app/node_modules/jwt-decode/build/esm/index")' has no call signatures.ts(2349)
//import jwt_decode from 'jwt-decode';
// In this case, you can use the following syntax:
import ChangePassword from "@/app/profile/settings/change-password/page";
import * as jwt_decode from "jwt-decode";
import { ApiError } from "next/dist/server/api-utils";

interface TokenPayload {
  _id: string;
  USER_NAME: string;
  exp?: number; 
}

// This will treat the library as any type, bypassing TypeScript's type checking:

export async function registerUser(firstName: string, lastName: string, userName: string, password: string, password2: string, email: string, terms: boolean, securityQuestion: string, securityAnswer: string) {
  let isActive = true;
  
  const timestamp = new Date().toISOString();
  //Format: "2022-03-14T11:45:26.079Z"

  console.log("API URL: " + process.env.NEXT_PUBLIC_API_URL);
  console.log("Body:"+JSON.stringify({ FIRST_NAME: firstName, LAST_NAME: lastName, USER_NAME: userName, USER_PASS: password, USER_PASS2: password2, EMAIL_ADDRESS: email, DATE_CREATED: timestamp, IS_ACTIVE: isActive, TERMS: terms, SECURITY_QUESTION: securityQuestion, SECURITY_ANSWER: securityAnswer}))
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/user/register`, {
    method: 'POST',
    body: JSON.stringify({ FIRST_NAME: firstName, LAST_NAME: lastName, USER_NAME: userName, USER_PASS: password, USER_PASS2: password2, EMAIL_ADDRESS: email, DATE_CREATED: timestamp, IS_ACTIVE: isActive, TERMS: terms, SECURITY_QUESTION: securityQuestion, SECURITY_ANSWER: securityAnswer}),
    headers: {
      'content-type': 'application/json',
    },
  });

  const data = await res.json();

  if (res.status === 200) {
    return true;
  } else {
    throw new Error(data.message);
  }
}

export async function authenticateUser(user: string, password: string) {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/user/login`, {
      method: 'POST',
      body: JSON.stringify({ userName: user, password: password }),
      headers: {
        'content-type': 'application/json',
      },
    });
  
    const data = await res.json();
  
    if (res.status === 200) {
      setToken(data.token);
      return data.id;
    } else {
      throw new Error(data.message);
    }
}

export async function authenticateFPUser(user: string, email: string, password?: string) {
  console.log("calling API from inside function ");
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/user/checkUnAuthenticatedUser`, {
    method: 'POST',
    body: JSON.stringify({ userName: user, email: email }),
    headers: {
      'content-type': 'application/json',
    },
  });

  const data = await res.json();

  if (res.status === 200) {
    setToken(data.token);
    return data.id;
  } else {
    throw new Error(data.message);
  }
}

export async function retrieveUser(user: string, securityAnswer: string) {
  console.log("calling retrieveUser API from inside function user: "+user+" securityAnswer: "+securityAnswer);
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/user/retrieveUser`, {
    method: 'POST',
    body: JSON.stringify({ userName: user, securityAnswer: securityAnswer }),
    headers: {
      'content-type': 'application/json',
    },
  });

  const data = await res.json();

  if (res.status === 200) {
    setToken(data.token);
    return data.id;
  } else {
    throw new Error(data.message);
  }
}

function setToken(token: string) {
    localStorage.setItem('access_token', token);
}


export function getToken() {
  try {
    return localStorage.getItem('access_token');
  } catch (err) {
    return null;
  }
}

export function removeToken() {
    localStorage.removeItem('access_token');
}

export function readToken(): TokenPayload | null {
  try {
      const token = getToken(); 
      if (!token) return null;

      let decoded = jwt_decode(token);
      const currentTime = Date.now() / 1000;

      if (decoded.exp && currentTime >= decoded.exp) {
          removeToken(); 
          return null;
      }

      return decoded; // Token is valid and not expired
  } catch (err) {
      console.error("Error decoding token:", err);
      return null;
  }
} 




export function isAuthenticated() {
    const token = readToken();
    return token ? true : false;
}