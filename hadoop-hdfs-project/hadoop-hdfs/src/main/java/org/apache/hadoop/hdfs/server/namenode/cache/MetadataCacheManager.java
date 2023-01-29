package org.apache.hadoop.hdfs.server.namenode.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.hops.metadata.hdfs.entity.Ace;
import io.hops.metadata.hdfs.entity.EncryptionZone;
import io.hops.metadata.hdfs.entity.StoredXAttr;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.server.namenode.INode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static org.apache.hadoop.hdfs.DFSConfigKeys.METADATA_CACHE_CAPACITY;
import static org.apache.hadoop.hdfs.DFSConfigKeys.METADATA_CACHE_CAPACITY_DEFAULT;

/**
 * Controls and manages access to several caches, each of which is responsible for caching a different type of metadata.
 *
 * The main cache is the {@link org.apache.hadoop.hdfs.server.namenode.cache.InMemoryINodeCache}.
 * This is the cache that stores the INodes, which are the primary metadata object used by HopsFS.
 * This class also manages a cache of {@link Ace} objects and a cache of {@link EncryptionZone} objects.
 *
 * The other caches are of type {@link org.apache.hadoop.hdfs.server.namenode.cache.ReplicaCache}, and these are managed by a separate {@link org.apache.hadoop.hdfs.server.namenode.cache.ReplicaCacheManager}.
 */
public class MetadataCacheManager {
    public static final Logger LOG = LoggerFactory.getLogger(MetadataCacheManager.class);

    /**
     * Caches INodes.
     */
    private final org.apache.hadoop.hdfs.server.namenode.cache.InMemoryINodeCache inodeCache;

    /**
     * Caches EncryptionZone instances. The key is INode ID.
     */
    private final Cache<Long, EncryptionZone> encryptionZoneCache;

    /**
     * Cache of Ace instances. Key is a string of the form [INodeID]-[Index], which is
     * the primary key of Ace instances in intermediate storage (NDB specifically).
     */
    private final Cache<String, Ace> aceCache;

    /**
     * We also maintain a list of all ace instances associated with a given INode,
     * so that we can invalidate these entries if the given INode gets modified.
     */
    private final Cache<Long, Set<CachedAce>> aceCacheByINodeId;

    /**
     * Cache for XAttr objects. They're associating with an INode.
     */
    private final Cache<String, StoredXAttr> xAttrCache;
    private final Cache<Long, Set<StoredXAttr>> xAttrCacheByINodeId;

    /**
     * Manages the caches associated with the various types of replicas.
     */
    private final org.apache.hadoop.hdfs.server.namenode.cache.ReplicaCacheManager replicaCacheManager;

    /**
     * Maximum elements in INode cache.
     */
    private final int cacheCapacity;

    public MetadataCacheManager(Configuration configuration) {
        this.cacheCapacity = configuration.getInt(METADATA_CACHE_CAPACITY, METADATA_CACHE_CAPACITY_DEFAULT);
        inodeCache = new org.apache.hadoop.hdfs.server.namenode.cache.InMemoryINodeCache(configuration);
        encryptionZoneCache = Caffeine.newBuilder()
                .initialCapacity(cacheCapacity)
                .maximumSize(cacheCapacity)
                .build();
        aceCache = Caffeine.newBuilder()
                .initialCapacity(cacheCapacity)
                .maximumSize(cacheCapacity)
                .build();
        aceCacheByINodeId = Caffeine.newBuilder()
                .initialCapacity(cacheCapacity)
                .maximumSize(cacheCapacity)
                .build();
        xAttrCache = Caffeine.newBuilder()
                .initialCapacity(cacheCapacity)
                .maximumSize(cacheCapacity)
                .build();
        xAttrCacheByINodeId = Caffeine.newBuilder()
                .initialCapacity(cacheCapacity)
                .maximumSize(cacheCapacity)
                .build();

//        encryptionZoneCache = new ConcurrentHashMap<>();
//        aceCache = new ConcurrentHashMap<>();
//        aceCacheByINodeId = new ConcurrentHashMap<>();

        this.replicaCacheManager = org.apache.hadoop.hdfs.server.namenode.cache.ReplicaCacheManager.getInstance();
    }

    public org.apache.hadoop.hdfs.server.namenode.cache.ReplicaCacheManager getReplicaCacheManager() { return this.replicaCacheManager; }

    public org.apache.hadoop.hdfs.server.namenode.cache.InMemoryINodeCache getINodeCache() { return inodeCache; }

    public int invalidateINodesByPrefix(String prefix) {
        Collection<INode> prefixedINodes = inodeCache.invalidateKeysByPrefix(prefix);

        if (prefixedINodes == null) return 0;

        for (INode node : prefixedINodes) {
            long inodeId = node.getId();
            invalidateAces(inodeId);
            invalidateXAttrs(inodeId);
            encryptionZoneCache.invalidate(inodeId);
        }

        return prefixedINodes.size();
    }

    public boolean invalidateINode(String key, boolean skipCheck) {
        INode node = inodeCache.getByPathNoMetrics(key);

        if (node != null) {
            long inodeId = node.getId();
            invalidateAces(inodeId);
            invalidateXAttrs(inodeId);
            encryptionZoneCache.invalidate(inodeId);
            //encryptionZoneCache.remove(inodeId);
        }

        return inodeCache.invalidateKey(key, skipCheck);
    }

    public void invalidateAllINodes() {
        encryptionZoneCache.invalidateAll();
        aceCache.invalidateAll();
        aceCacheByINodeId.invalidateAll();
//        encryptionZoneCache.clear();
//        aceCache.clear();
//        aceCacheByINodeId.clear();
        inodeCache.invalidateEntireCache();
    }

    public boolean invalidateINode(long inodeId) {
        invalidateAces(inodeId);
        encryptionZoneCache.invalidate(inodeId);
        invalidateXAttrs(inodeId);
        //encryptionZoneCache.remove(inodeId);
        return inodeCache.invalidateKey(inodeId);
    }

    private void invalidateXAttrs(long inodeId) {
        Set<StoredXAttr> cachedXAttrs = xAttrCacheByINodeId.getIfPresent(inodeId);

        if (cachedXAttrs == null)
            return;

        for (StoredXAttr cachedXAttr : cachedXAttrs) {
            String key = getXAttrKey(cachedXAttr.getInodeId(), cachedXAttr.getNamespace(), cachedXAttr.getName());
            xAttrCache.invalidate(key);
            //aceCache.remove(key);
        }

        cachedXAttrs.clear();
    }

    private void invalidateAces(long inodeId) {
        Set<CachedAce> cachedAces = aceCacheByINodeId.getIfPresent(inodeId); // aceCacheByINodeId.getOrDefault(inodeId, null);

        if (cachedAces == null)
            return;

        for (CachedAce cachedAce : cachedAces) {
            String key = getAceKey(cachedAce.inodeId, cachedAce.index);
            aceCache.invalidate(key);
            //aceCache.remove(key);
        }

        cachedAces.clear();
    }

    /**
     * Return the EncryptionZone cached at the given key, or null if it does not exist.
     * @param inodeId The ID of the associated INode.
     * @return The EncryptionZone cached at the given key, or null if it does not exist.
     */
    public EncryptionZone getEncryptionZone(long inodeId) {
        return encryptionZoneCache.getIfPresent(inodeId);
        //return encryptionZoneCache.getOrDefault(inodeId, null);
    }

    /**
     * Cache the given EncryptionZone instance at the given key.
     */
    public void putEncryptionZone(long inodeId, EncryptionZone encryptionZone) {
        encryptionZoneCache.put(inodeId, encryptionZone);
    }

    /**
     * Return the Ace instance cached with the given INode ID and index field.
     * Returns null if no such Ace instance exists.
     */
    public Ace getAce(long inodeId, int index) {
        String key = getAceKey(inodeId, index);
        return aceCache.getIfPresent(key);
        //return aceCache.getOrDefault(key,null);
    }

    public StoredXAttr getStoredXAttr(long inodeId, byte namespace, String name) {
        String key = getXAttrKey(inodeId, namespace, name);
        return xAttrCache.getIfPresent(key);
    }

    public void putStoredXAttr(long inodeId, byte namespace, String name, StoredXAttr xattr) {
        String key = getXAttrKey(inodeId, namespace, name);
        xAttrCache.put(key, xattr);
    }

    /**
     * Cache the given Ace object with a key generated by the INode ID and the index.
     */
    public void putAce(long inodeId, int index, Ace ace) {
        String key = getAceKey(inodeId, index);
        aceCache.put(key, ace);

        CachedAce cachedAce = new CachedAce(inodeId, index, ace);
        Set<CachedAce> cachedAces = aceCacheByINodeId.getIfPresent(inodeId); // aceCacheByINodeId.getOrDefault(inodeId, null);

        if (cachedAces == null) {
            cachedAces = new HashSet<>();
            aceCacheByINodeId.put(inodeId, cachedAces);
        }

        cachedAces.add(cachedAce);
    }

    /**
     * Return the key generated by a given INode ID and an index (for an Ace instance).
     */
    private String getAceKey(long inodeId, int index) {
        return inodeId + "-" + index;
    }

    /**
     * Return the key generated by the components of a StoredXAttr primary key.
     */
    private String getXAttrKey(long inodeId, byte namespace, String name) {
        return inodeId + "-" + namespace + "-" + name;
    }

    /**
     * We maintain two Caches for Ace instances. One cache maps their primary key (INode ID and index) to a singular
     * Ace index. The other cache maps INode IDs to CachedAce instances. We do this so that, if the INode gets
     * invalidated, then we can find all the Ace instances we have cached for that INode and invalidate them
     * as well.
     */
    private static class CachedAce {
        /**
         * INode ID of the INode associated with this Ace object.
         */
        long inodeId;

        /**
         * Index/ID of this Ace object. Used as part of the primary key.
         */
        int index;

        /**
         * The actual Ace object that we're caching (and that this class is wrapping).
         */
        Ace ace;

        CachedAce(long inodeId, int index, Ace ace) {
            this.inodeId = inodeId;
            this.index = index;
            this.ace = ace;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj instanceof CachedAce){
                CachedAce other = (CachedAce) obj;
                return inodeId == other.inodeId && index == other.index;
            }
            return false;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 31 * hash + index;
            hash = 31 * hash + Long.hashCode(inodeId);
            return hash;
        }
    }
}
