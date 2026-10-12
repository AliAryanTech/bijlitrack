'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import api from '../lib/api';
import { useRouter } from 'next/navigation';

interface User {
  id: string;
  name: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  activeRefId: string | null;
  setActiveRefId: (id: string | null) => void;
  login: (userDataOrToken: any, userData?: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [activeRefId, setActiveRefIdState] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const savedRefId = localStorage.getItem('activeRefId');
    if (savedRefId) setActiveRefIdState(savedRefId);

    const initAuth = async () => {
      try {
        const res = await api.get('/auth/me');
        setUser(res.data);
      } catch (error: any) {
        // Only clear user on 401 Unauthorized
        if (error?.response?.status === 401) {
          setUser(null);
          localStorage.removeItem('token');
        } else {
          console.warn('Auth check failed (network/server error). Retrying...', error?.message);
          try {
            await new Promise((resolve) => setTimeout(resolve, 3000));
            const retryRes = await api.get('/auth/me');
            setUser(retryRes.data);
          } catch (retryError: any) {
            setUser(null);
            if (retryError?.response?.status === 401) {
              localStorage.removeItem('token');
            }
          }
        }
      } finally {
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  const setActiveRefId = (id: string | null) => {
    setActiveRefIdState(id);
    if (id) {
      localStorage.setItem('activeRefId', id);
    } else {
      localStorage.removeItem('activeRefId');
    }
  };

  const login = (first: any, second?: any) => {
    let userData: User;
    if (second) {
      userData = second;
      if (typeof first === 'string' && first) {
        localStorage.setItem('token', first);
      }
    } else {
      userData = first;
    }
    setUser(userData);
    router.push('/dashboard');
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.warn('Logout API failed:', e);
    }
    localStorage.removeItem('token');
    localStorage.removeItem('activeRefId');
    setUser(null);
    setActiveRefIdState(null);
    router.push('/login');
  };

  return (
    <AuthContext.Provider value={{ user, loading, activeRefId, setActiveRefId, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
