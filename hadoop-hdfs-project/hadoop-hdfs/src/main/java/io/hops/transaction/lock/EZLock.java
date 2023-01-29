/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.hops.transaction.lock;

import io.hops.metadata.hdfs.entity.EncryptionZone;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import io.hops.transaction.EntityManager;
import org.apache.hadoop.hdfs.server.namenode.INode;

public class EZLock extends Lock {
  private final TransactionLockTypes.LockType lockType;

  /**
   * Creates a new EZLock instance. This instance will use the default lock type, whatever that is.
   */
  public EZLock() {
    lockType = DEFAULT_LOCK_TYPE;
  }

  /**
   * Creates a new EZLock instance, specifying the lock type to use.
   */
  public EZLock(TransactionLockTypes.LockType lockType) {
    this.lockType = lockType;
  }
  
  @Override
  public void acquire(TransactionLocks locks) throws IOException {
    BaseINodeLock inodeLock = (BaseINodeLock) locks.getLock(Type.INode);
    List<Long> inodeIds = new ArrayList<>();
    for (INode inode : inodeLock.getAllResolvedINodes()) {
      inodeIds.add(inode.getId());
    }
    if (!inodeIds.isEmpty()) {
      // The locking should have been done on the INodes, so it does not matter which lock we take here.
      acquireLockList(this.lockType, EncryptionZone.Finder.ByPrimaryKeyBatch, inodeIds);
    }
  }

  @Override
  public Type getType() {
    return Type.EZ;
  }
}
