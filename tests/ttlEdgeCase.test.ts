import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('AuditPulse TTL Storage Edge Case Fixture', () => {
  const contractPath = path.join(__dirname, '../contracts/TtlStorageEdgeCase.rs');

  it('should verify the new TTL edge case contract exists in contracts/', () => {
    expect(fs.existsSync(contractPath)).toBe(true);
  });

  it('should contain temporary, persistent, and instance TTL extensions', () => {
    const code = fs.readFileSync(contractPath, 'utf-8');
    
    expect(code).toContain('env.storage().temporary()');
    expect(code).toContain('extend_ttl');
    expect(code).toContain('env.storage().persistent()');
    expect(code).toContain('env.storage().instance()');
  });
});
