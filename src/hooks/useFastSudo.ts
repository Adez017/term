// src/hooks/useFastSudo.ts
import { invoke } from '@tauri-apps/api/core';
import { useState, useCallback } from 'react';

interface SudoRequest {
  command: string;
  args: string[];
  password?: string;
}

interface SudoResponse {
  success: boolean;
  output: string;
  error?: string;
  cached: boolean;
  needs_password: boolean;
}

export const useFastSudo = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [needsPassword, setNeedsPassword] = useState(false);

  const executeSudo = useCallback(async (request: SudoRequest): Promise<SudoResponse> => {
    setIsLoading(true);
    try {
      const response = await invoke<SudoResponse>('fast_sudo', { request });
      
      setNeedsPassword(response.needs_password);
      
      return response;
    } catch (error) {
      console.error('Fast sudo error:', error);
      return {
        success: false,
        output: '',
        error: `Failed to execute sudo command: ${error}`,
        cached: false,
        needs_password: false,
      };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const clearCache = useCallback(async (): Promise<void> => {
    try {
      await invoke('clear_sudo_cache');
      setNeedsPassword(false);
    } catch (error) {
      console.error('Failed to clear sudo cache:', error);
    }
  }, []);

  const checkPrivileges = useCallback(async (): Promise<boolean> => {
    try {
      return await invoke<boolean>('check_sudo_privileges');
    } catch (error) {
      console.error('Failed to check sudo privileges:', error);
      return false;
    }
  }, []);

  return {
    executeSudo,
    clearCache,
    checkPrivileges,
    isLoading,
    needsPassword,
  };
};

export const parseSudoCommand = (input: string): { command: string; args: string[] } | null => {
  const trimmed = input.trim();
  const parts = trimmed.split(/\s+/);
  
  if (parts.length < 2 || parts[0] !== 'sudo') {
    return null;
  }
  
  return {
    command: parts[1],
    args: parts.slice(2),
  };
};