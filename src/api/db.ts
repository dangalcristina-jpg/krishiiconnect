import { createClient, type SupabaseClient } from '@supabase/supabase-js';

function readEnv() {
  const url = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY;
  return { url, key };
}

let _client: SupabaseClient | null = null;

export function getDb(): SupabaseClient {
  if (_client) return _client;
  const { url, key } = readEnv();
  if (!url || !key) {
    throw new Error('Supabase env vars missing — set SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY');
  }
  _client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return _client;
}

// Backwards-compatible `db` export that lazily proxies to getDb().
export const db = new Proxy({} as SupabaseClient, {
  get(_t, prop) {
    const client = getDb();
    const value = (client as unknown as Record<string | symbol, unknown>)[prop];
    return typeof value === 'function' ? value.bind(client) : value;
  },
});

export interface User {
  id: string;
  full_name: string;
  business_name: string | null;
  phone: string;
  pin_hash: string;
  phone_verified: boolean;
  role: 'farmer' | 'wholesaler' | 'admin';
  status: 'active' | 'suspended' | 'banned';
  farm_location: string | null;
  years_experience: number | null;
  about_farm: string | null;
  business_location: string | null;
  years_in_business: number | null;
  storage_capacity_tons: number | null;
  avatar_url: string | null;
  created_at: string;
}

export interface Crop {
  id: string;
  farmer_id: string;
  name: string;
  category: string | null;
  price: number;
  quantity_available: number;
  unit: string;
  location: string | null;
  harvest_date: string | null;
  image_url: string | null;
  description: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'sold_out';
  created_at: string;
  farmer?: User;
}

export interface Order {
  id: string;
  wholesaler_id: string;
  farmer_id: string;
  crop_id: string;
  quantity: number;
  status: 'pending' | 'completed' | 'cancelled';
  created_at: string;
  crop?: Crop;
  farmer?: User;
  wholesaler?: User;
}

export interface MarketPrice {
  id: string;
  product: string;
  unit: string;
  min_price: number;
  max_price: number;
  avg_price: number;
  trend: 'up' | 'down' | 'stable';
  updated_at: string;
}

export interface Review {
  id: string;
  order_id: string;
  reviewer_id: string;
  reviewee_id: string;
  reviewer_role: 'farmer' | 'wholesaler';
  rating: number;
  comment: string | null;
  created_at: string;
  reviewer?: User;
  order?: Order;
}

export interface Product {
  id: string;
  farmer_id: string;
  product_name: string;
  category: string;
  description: string | null;
  price: number;
  quantity: number;
  unit: string;
  district: string;
  municipality: string | null;
  harvest_date: string | null;
  availability: 'Available' | 'Limited Stock' | 'Sold Out';
  created_at: string;
  updated_at: string;
  images?: ProductImage[];
}

export interface ProductImage {
  id: string;
  product_id: string;
  image_url: string;
  sort_order: number;
  created_at: string;
}

export interface CropImage {
  id: string;
  crop_id: string;
  image_url: string;
  sort_order: number;
  created_at: string;
}

export interface OtpCode {
  id: string;
  phone: string;
  code: string;
  purpose: 'register' | 'reset_pin';
  expires_at: string;
  used: boolean;
  created_at: string;
}

export interface ContactRow {
  id: string;
  name: string;
  email: string;
  message: string;
  created_at: string;
}

export interface SessionRow {
  id: string;
  token: string;
  user_id: string;
  created_at: string;
  expires_at: string;
}
