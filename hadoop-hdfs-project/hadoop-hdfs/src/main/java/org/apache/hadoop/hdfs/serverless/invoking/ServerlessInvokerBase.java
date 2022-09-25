package org.apache.hadoop.hdfs.serverless.invoking;

import com.google.common.hash.Hashing;
import com.google.gson.*;
import io.hops.metrics.TransactionEvent;
import io.hops.transaction.context.TransactionsStats;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.serverless.OpenWhiskHandler;
import org.apache.hadoop.hdfs.serverless.ServerlessNameNodeKeys;
import org.apache.hadoop.hdfs.serverless.cache.FunctionMetadataMap;
import org.apache.hadoop.hdfs.serverless.execution.results.NullResult;
import org.apache.hadoop.hdfs.serverless.userserver.ServerAndInvokerManager;
import org.apache.hadoop.hdfs.serverless.execution.futures.ServerlessHttpFuture;
import org.apache.hadoop.util.ExponentialBackOff;
import org.apache.hadoop.util.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.impl.nio.reactor.IOReactorConfig;
import org.apache.http.nio.conn.NoopIOSessionStrategy;
import org.apache.http.nio.conn.SchemeIOSessionStrategy;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.nio.reactor.IOReactorException;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.*;
import java.io.*;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;

import static org.apache.hadoop.hdfs.DFSConfigKeys.*;
import static org.apache.hadoop.hdfs.serverless.ServerlessNameNodeKeys.*;
import static com.google.common.hash.Hashing.consistentHash;
import static org.apache.hadoop.hdfs.serverless.invoking.ServerlessUtilities.extractParentPath;

/**
 * Base class of serverless invokers. Defines some concrete state (i.e., instance variables) used by
 * all serverless invokers.
 *
 * We use this class to generically refer to a serverless invoker regardless of what platform is being used. This
 * keeps the code cleaner/simpler. When writing code to invoke NameNodes, we don't have to consider which serverless
 * platform is being used. Instead, we just refer to this class, and we use the {@link ServerlessInvokerFactory} class
 * to obtain a concrete subclass in which the function logic is implemented.
 *
 * Traditionally, a client would call {@link org.apache.hadoop.hdfs.DistributedFileSystem#create(Path)} (for example)
 * when they want to create a file. Under the covers, this call would propagate to the
 * {@link org.apache.hadoop.hdfs.DFSClient} class. Then an RPC call would occur between the DFSClient and a remote
 * NameNode. Now, instead of using RPC, we use an HTTP request. The recipient of the HTTP request is the OpenWhisk
 * API Gateway, which will route our request to a NameNode container. As such, we must include in the HTTP request
 * the name of the function we want the NameNode to execute along with the function's arguments. We also pass
 * various configuration parameters, debug information, etc. in the HTTP payload. The NameNode will execute the
 * function for us, then return a result via HTTP.
 *
 * The DFSClient class used to maintain an RPC interface to a remote NameNode of type
 * {@link org.apache.hadoop.hdfs.protocol.ClientProtocol}. I believe this was essentially just a reference to the
 * {@link org.apache.hadoop.hdfs.server.namenode.NameNodeRpcServer} instance running on the remote NameNode. To replace
 * this, I created a new class {@link ServerlessNameNodeClient} which implements the ClientProtocol interface. The
 * DFSClient class now calls methods on the ServerlessNameNodeClient object. Instead of being RPC methods, the
 * ServerlessNameNodeClient transparently issues HTTP/TCP requests to invoke NameNode functions. The
 * ServerlessNameNodeClient class interacts with a concrete child class of this ServerlessInvokerBase class to
 * invoke NameNode functions (e.g., the {@link OpenWhiskInvoker} class).
 *
 * The "main" API exposed by this class is the {@code invokeNameNodeViaHttpPost} function, which issues an HTTP POST
 * to the API Gateway of the serverless platform. (It doesn't have to be the API Gateway; that's just often what the
 * serverless platform component is. We issue a request to whatever we're supposed to in order to invoke functions. In
 * the case of OpenWhisk, that's the API Gateway component.)
 *
 * TODO: Put metrics all on ServerlessNameNodeClient.
 */
public abstract class ServerlessInvokerBase {
    private static final Log LOG = LogFactory.getLog(ServerlessInvokerBase.class);

    private static final String CONTAINS_SUBTREE_OP = "CONTAINS_SUBTREE_OP";

    protected Registry<ConnectionSocketFactory> registry;

    private static final Random rng = new Random();

    /**
     * The set of request IDs that have been processed from the request queue and are ready to be sent.
     * If an error occurs during processing, then these already-processed requests can be cancelled rather
     * than having the request fail silently.
     */
    protected static Set<String> processedRequestIds = ConcurrentHashMap.newKeySet();

    /**
     * Request IDs enqueued for submission that are subtree operations, and thus will need to be
     * submitted with a higher request timeout than usual.
     */
    protected static Set<String> subtreeRequests = ConcurrentHashMap.newKeySet();

    /**
     * Store the statistics packages from serverless name nodes in this HashMap.
     *
     * Map from request ID to statistics packages.
     */
    private static ConcurrentHashMap<String, TransactionsStats.ServerlessStatisticsPackage> statisticsPackages
            = new ConcurrentHashMap<>();

    /**
     * Store the transaction events from serverless name nodes in this HashMap.
     *
     * Map from request ID to statistics packages.
     */
    private static ConcurrentHashMap<String, List<TransactionEvent>> transactionEvents = new ConcurrentHashMap<>();

    /**
     * Flag indicating whether we are running in 'local mode', which is only relevant on the client-side.
     * If true, then there's only one NameNode running within a Docker container on the same VM as the HopsFS client.
     *
     * This is only used for debugging/profiling/testing.
     */
    protected boolean localMode;

    /**
     * Flag indicated whether the invoker has been configured.
     * The invoker must be configured via `setConfiguration` before it can be used.
     */
    protected volatile boolean configured = false;

    /**
     * HTTPClient used to invoke serverless functions.
     */
    protected CloseableHttpAsyncClient httpClient;

    /**
     * Maintains a mapping of files and directories to the serverless functions responsible for caching the
     * metadata of the file/directory in question.
     */
    protected FunctionMetadataMap cache;

    /**
     * The number of uniquely-deployed serverless functions available for use.
     */
    protected int numDeployments;

    /**
     * Indicates whether this Invoker instance is used by a client/user. When false, indicates that this
     * Invoker is useb by a DataNode.
     */
    protected boolean isClientInvoker;

    /**
     * Mapping from request ID to the associated futures.
     */
    private final ConcurrentHashMap<String, ServerlessHttpFuture> futures;

    /**
     * Name of the entity using this invoker.
     *
     * For DataNodes, this is DN-[the DataNode's transfer IP]:[the DataNode's transfer port].
     * For Clients, this is C-[the client's ID].
     * For NameNodes, this is NN[DeploymentNumber]-[the NameNode's ID].
     */
    protected String invokerIdentity;

    /**
     * Unique identifier of the particular client using this class.
     *
     * This name will be set automatically if a client/user is invoking. Otherwise, we default to DataNode.
     */
    protected String clientName = "DataNode";

    /**
     * If true, then we'll pass an argument to the NNs indicating that they should print their
     * debug output from the underlying NDB C++ library (libndbclient.so).
     */
    protected boolean debugEnabledNdb = false;

    /**
     * This string is passed to the NDB C++ library (on the NameNodes) if NDB debugging is enabled.
     */
    protected String debugStringNdb = null;

    /**
     * Maximum number of retries to be attempted for failed HTTP requests (response code in range [400, 599]).
     */
    protected int maxHttpRetries = DFSConfigKeys.SERVERLESS_HTTP_RETRY_MAX_DEFAULT;

    /**
     * If True, then we'll tell the NameNodes how to connect to this client's TCP server.
     * If False, then we'll tell the NameNodes not to try connecting to the TCP server.
     */
    protected boolean tcpEnabled;
    protected boolean udpEnabled;

    /**
     * The TCP port that we ultimately bound to. See the comment in 'ServerlessNameNodeClient' for its
     * 'tcpServerPort' instance field for explanation as to why this field exists.
     */
    protected volatile int tcpPort;

    protected volatile int udpPort;

    /**
     * The timeout, in milliseconds, for an HTTP request to a NameNode. This specifically
     * is the timeout for a connection to be established with the server. Timed-out requests
     * will be retried according to the maxHttpRetries instance variable.
     */
    protected int httpTimeoutMilliseconds;

    /**
     * The log level argument to be passed to serverless functions.
     */
    protected String serverlessFunctionLogLevel = "DEBUG";

    /**
     * Passed to serverless functions. Determines whether they execute the consistency protocol.
     */
    protected volatile boolean consistencyProtocolEnabled = true;

    /**
     * Turns off metric collection to save time, network transfer, and memory.
     */
    protected volatile boolean benchmarkModeEnabled = false;

    /**
     * Outgoing requests are placed in this list and sent in batches
     * (of a configurable size) on a configurable interval.
     */
    private LinkedBlockingQueue<JsonObject>[] outgoingRequests;

    /**
     * We batch individual requests together to reduce per-request overhead.
     * This is the number of requests per batch.
     */
    protected int batchSize;

    /**
     * The interval, in milliseconds, that HTTP requests are issued.
     */
    protected int sendInterval;

    protected String functionUriBase;

    /**
     * This is used to issue all queued requests on an interval.
     */
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    /**
     * Default constructor.
     */
    protected ServerlessInvokerBase() {
        this.futures = new ConcurrentHashMap<>();
    }

    /**
     * IMPORTANT:
     * This function should call the {@link ServerlessInvokerBase#addStandardArguments(JsonObject)} function. This is
     * done to ensure that the NameNode has all of the required information necessary to properly handle the request.
     *
     * This function should also call {@link ServerlessInvokerBase#createRequestBatches(List)} and use the
     * returned {@code List<List<JsonArray>>} object to send the requests.
     */
    protected abstract void sendEnqueuedRequests()
            throws UnsupportedEncodingException, SocketException, UnknownHostException;

    public void setBenchmarkModeEnabled(boolean benchmarkModeEnabled) {
        this.benchmarkModeEnabled = benchmarkModeEnabled;
    }

    /**
     * Merges the requests from each deployment into batches (of a configurable maximum size).
     * The batched requests are returned. These batches will then be issued in requests to the respective deployment.
     * The invocations should occur in the {@link ServerlessInvokerBase#sendEnqueuedRequests()} function, which is
     * abstract and thus will be implemented by a subclass of {@link ServerlessInvokerBase}.
     *
     * Each batch of requests will be processed by a single NameNode. The results of the entire batch will be
     * returned all at once, rather than one-at-a-time.
     *
     * @param batchedRequests Empty list that will be populated with batches of requests.
     * @return The number of requests that we placed into batches.
     *
     * Each {@link JsonObject} contains a batch of requests.
     */
    protected int createRequestBatches(List<List<JsonObject>> batchedRequests) {
        // Old return documentation:
        // @return Batches of requests by deployment. Entry i in the returned list corresponds to deployment i.
        if (batchedRequests.size() > 0)
            throw new IllegalArgumentException("The batchedRequests list must be initially empty.");

        // Iterate over the request queue for each of the deployments.
        // For each queue, we check if it has at least one enqueued request.
        // If there are none, then we skip that queue.
        // If it has at least one request, then we partition however many requests there are into batches.
        int totalNumRequests = 0;
        for (int i = 0; i < numDeployments; i++) {
            LinkedBlockingQueue<JsonObject> deploymentQueue = outgoingRequests[i];

            // This will just be empty if there are no requests queued for this deployment.
            List<JsonObject> deploymentBatches = new ArrayList<>();
            batchedRequests.add(deploymentBatches);

            // Does this queue have at least one request?
            if (deploymentQueue.size() > 0) {
                if (LOG.isDebugEnabled()) LOG.debug("Deployment " + i + " has " + deploymentQueue.size() + " requests enqueued...");

                JsonObject currentBatch = new JsonObject();
                deploymentBatches.add(currentBatch);

                // Process all requests in the queue. Note that other requests could be added while processing.
                // These requests will presumably end up being processed now, rather than the next time we do this.
                while (deploymentQueue.size() > 0) {
                    JsonObject request = deploymentQueue.poll();

                    if (request == null) {
                        LOG.error("Received null from request queue for deployment " + i +
                                " while invoking HTTP requests. Queue size: " + deploymentQueue.size());

                        // This situation really shouldn't happen... But we just continue to the next iteration.
                        // If the queue is empty, then the while-loop will terminate. Otherwise, we'll process
                        // whatever requests are in the queue.
                        continue;
                    }

                    String requestId = request.get(REQUEST_ID).getAsString();

                    if (subtreeRequests.contains(requestId)) {
                        LOG.info("Request " + requestId +
                                " is a subtree operation. Current batch contains a subtree operation.");
                        currentBatch.addProperty(CONTAINS_SUBTREE_OP, true);
                    }

                    currentBatch.add(requestId, request);
                    totalNumRequests++;

                    // If the current batch's size is equal to that of the batch size parameter,
                    // then we need to start a new batch.
                    if (currentBatch.size() > batchSize) {
                        if (LOG.isTraceEnabled()) LOG.trace("Current batch for deployment " + i +
                                " has reached maximum size (" + batchSize + "). Starting new batch.");

                        // If there are more outgoing requests to process for this deployment, then create a new batch.
                        if (deploymentQueue.size() > 0) {
                            currentBatch = new JsonObject();
                            deploymentBatches.add(currentBatch);
                        }
                    }

                    // The request has been fully processed and is ready to be sent, so add it to the set.
                    processedRequestIds.add(requestId);
                }
            }
        }

        if (LOG.isTraceEnabled() && totalNumRequests > 0) LOG.trace("Partitioned a total of " + totalNumRequests +
                " request(s) into batches.");
        return totalNumRequests;
    }

    /**
     * Extract the actual result payload returned by the NameNode. The result payload will be given to the client.
     * @param httpResponse The HTTP response returned by the HTTP request.
     * @return The result payload returned by the NameNode.
     */
    protected JsonObject processHttpResponse(HttpResponse httpResponse) throws IOException {
        String json = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        Gson gson = new Gson();

        JsonObject jsonObjectResponse;
        JsonPrimitive jsonPrimitiveResponse;

        // If there was an OpenWhisk error, like a 502 Bad Gateway (for example), then this will
        // be a JsonPrimitive object. Specifically, it'd be a String containing the error message.
        try {
            jsonObjectResponse = gson.fromJson(json, JsonObject.class);
        } catch (JsonSyntaxException ex) {
            jsonPrimitiveResponse = gson.fromJson(json, JsonPrimitive.class);

            throw new IOException("Unexpected response from OpenWhisk function invocation: "
                    + jsonPrimitiveResponse.getAsString());
        }

        return jsonObjectResponse;
    }

    /**
     * Create a TrustManager that does not validate certificate chains.
     *
     * This is necessary because otherwise, we may encounter SSL certificate errors when invoking serverless functions.
     * I do not know all the details behind this, but this resolves the errors.
     *
     * In the future, we may want to add certificate support for increased security, with a fall-back to this being an
     * option if the users do not want to configure SSL certificates.
     *
     * Per the Java documentation, TrustManagers are responsible for managing the trust material that is used when
     * making trust decisions, and for deciding whether credentials presented by a peer should be accepted.
     */
    private void instantiateTrustManagerOriginal() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (GeneralSecurityException e) {
            LOG.error(e);
        }
    }

    /**
     * Get the TCP port being used by this client's TCP server.
     * @return The TCP port being used by this client's TCP server.
     */
    public int getTcpPort() {
        return tcpPort;
    }

    /**
     * Update the TCP port being used by this client's TCP server.
     * @param tcpPort The new value for the TCP port.
     */
    public synchronized void setTcpPort(int tcpPort) {
        this.tcpPort = tcpPort;
    }

    /**
     * Update the UDP port being used by this client's UDP server.
     * @param udpPort The new value for the UDP port.
     */
    public synchronized void setUdpPort(int udpPort) {
        this.udpPort = udpPort;
    }

    /**
     * Set parameters of the invoker specified in the HopsFS configuration.
     */
    public void setConfiguration(Configuration conf, String invokerIdentity, String functionUriBase) {
        if (configured) return;

        //if (LOG.isDebugEnabled()) LOG.debug("Configuring ServerlessInvokerBase now...");

        // cache = new FunctionMetadataMap(conf);
        localMode = conf.getBoolean(SERVERLESS_LOCAL_MODE, SERVERLESS_LOCAL_MODE_DEFAULT);
        maxHttpRetries = conf.getInt(DFSConfigKeys.SERVERLESS_HTTP_RETRY_MAX,
                DFSConfigKeys.SERVERLESS_HTTP_RETRY_MAX_DEFAULT);
        tcpEnabled = conf.getBoolean(DFSConfigKeys.SERVERLESS_TCP_REQUESTS_ENABLED,
                DFSConfigKeys.SERVERLESS_TCP_REQUESTS_ENABLED_DEFAULT);
        udpEnabled = conf.getBoolean(SERVERLESS_USE_UDP, SERVERLESS_USE_UDP_DEFAULT);
        httpTimeoutMilliseconds = conf.getInt(DFSConfigKeys.SERVERLESS_HTTP_TIMEOUT,
                DFSConfigKeys.SERVERLESS_HTTP_TIMEOUT_DEFAULT) * 1000; // Convert from seconds to milliseconds.
        batchSize = conf.getInt(SERVERLESS_HTTP_BATCH_SIZE, SERVERLESS_HTTP_BATCH_SIZE_DEFAULT);
        sendInterval = conf.getInt(SERVERLESS_HTTP_SEND_INTERVAL, SERVERLESS_HTTP_SEND_INTERVAL_DEFAULT);
        this.functionUriBase = functionUriBase;

        if (this.localMode)
            numDeployments = 1;
        else
            numDeployments = conf.getInt(DFSConfigKeys.SERVERLESS_MAX_DEPLOYMENTS, DFSConfigKeys.SERVERLESS_MAX_DEPLOYMENTS_DEFAULT);

        this.invokerIdentity = invokerIdentity;

        // NDB
        debugEnabledNdb = conf.getBoolean(DFSConfigKeys.NDB_DEBUG, DFSConfigKeys.NDB_DEBUG_DEFAULT);
        debugStringNdb = conf.get(DFSConfigKeys.NDB_DEBUG_STRING, DFSConfigKeys.NDB_DEBUG_STRING_DEFAULT);
//        if (LOG.isDebugEnabled()) {
//            LOG.debug("NDB debug enabled: " + debugEnabledNdb);
//            LOG.debug("TCP Enabled: " + tcpEnabled);
//            LOG.debug("UDP Enabled: " + udpEnabled);
//            LOG.debug("Batch size: " + batchSize);
//            LOG.debug("Send interval: " + sendInterval);
//
//            if (debugEnabledNdb) LOG.debug("NDB debug string: " + debugStringNdb);
//        }

        try {
            httpClient = getHttpClient();
        } catch (NoSuchAlgorithmException | KeyManagementException | CertificateException | KeyStoreException | IOReactorException e) {
            e.printStackTrace();
            return;
        }

        //if (LOG.isDebugEnabled()) LOG.debug("Starting async HTTP client now...");
        httpClient.start();
        //if (LOG.isDebugEnabled()) LOG.debug("Started async HTTP client.");

        outgoingRequests = new LinkedBlockingQueue[numDeployments];

        // Create an outgoing request queue for each deployment.
        for (int i = 0; i < numDeployments; i++) {
            outgoingRequests[i] = new LinkedBlockingQueue<>();
        }

        configured = true;

        // Schedule the processing and sending of enqueued HTTP requests on a schedule with fixed delay.
        // This means that the scheduled operation will execute `sendInterval` milliseconds after the previous
        // execution completes. This will occur indefinitely.
        scheduler.scheduleWithFixedDelay(
                this::scheduledRequestProcessor, sendInterval, sendInterval, TimeUnit.MILLISECONDS);
    }

    /**
     * This method is executed by a {@link ScheduledExecutorService} instance every
     * {@link ServerlessInvokerBase#sendInterval} milliseconds.
     */
    private void scheduledRequestProcessor() {
        try {
            sendEnqueuedRequests();
        } catch (Exception e) {
            LOG.error("Exception encountered while issuing HTTP requests:", e);
            handleAlreadyProcessedRequestsOnException();
        } finally {
            // Each time we process the enqueued requests, we clear this set and the subtreeRequests set.
            processedRequestIds.clear();
            subtreeRequests.clear();
        }
    }

    /**
     * If an exception occurs while preparing enqueued HTTP requests to be transmitted,
     * then the already-processed HTTP requests need to be cancelled.
     */
    private void handleAlreadyProcessedRequestsOnException() {
        LOG.warn("The following requests have already been processed and must now be cancelled: " +
                StringUtils.join(", ", processedRequestIds));

        int totalNumFuturesCancelled = 0;
        for (String requestId : processedRequestIds) {
            ServerlessHttpFuture future = futures.get(requestId);
            if (future != null) {
                // TODO: Change this to trace.
                if (LOG.isDebugEnabled()) LOG.debug("Cancelling future associated with HTTP request " + requestId);
                future.cancel(true);
                totalNumFuturesCancelled++;
            }
        }

        if (LOG.isDebugEnabled()) LOG.debug("Cancelled " + totalNumFuturesCancelled + "/" +
                processedRequestIds.size() + " future(s).");
    }

    /**
     * Enqueue an outgoing request to a particular deployment.
     * This request will be batched with other requests to the same deployment.
     * @param requestArguments JsonObject encapsulating all arguments and information related to the request. This
     *                         is what gets sent to the NameNode.
     * @param targetDeployment The deployment to which this request is to be directed.
     */
    private void enqueueRequest(JsonObject requestArguments, int targetDeployment) {
        outgoingRequests[targetDeployment].add(requestArguments);
    }

    public void setConsistencyProtocolEnabled(boolean enabled) {
        this.consistencyProtocolEnabled = enabled;
    }

    public void setServerlessFunctionLogLevel(String logLevel) {
        this.serverlessFunctionLogLevel = logLevel;
    }

    /**
     * This is the public-facing API for enqueuing an HTTP request for submission. Requests are invoked asynchronously
     * and in a batched manner, meaning individual requests to the same deployment are batched together into larger
     * requests. The number of individual requests in a batch is configurable. Each batch of requests is delivered
     * to a single NameNode for processing.
     *
     * This function is implemented by each subclass of {@link ServerlessInvokerBase} in order to handle invocation
     * logic specific to a particular serverless platform. For example, different platforms will likely expect
     * arguments to be included in the HTTP request payload in different ways (or under different keys).
     *
     * @param operationName The FS operation being performed. This is passed to the NameNode so that it knows which of
     *                      its functions it should execute. This is sort of taking the place of the RPC mechanism,
     *                      where ordinarily you'd just invoke an RPC method.
     * @param functionUriBase The base URI of the serverless function. We issue an HTTP request to this URI
     *                        in order to invoke the function. Before the request is issued, a number is appended
     *                        to the end of the URI to target a particular serverless name node. After the number is
     *                        appended, we also append a string ?blocking=true to ensure that the operation blocks
     *                        until it is completed so that the result may be returned to the caller.
     * @param nameNodeArguments Arguments for the Name Node itself. These would traditionally be passed as command line
     *                          arguments when using a serverful name node. We generally don't need to pass anything
     *                          for this parameter.
     * @param fileSystemOperationArguments The parameters to the FS operation. Specifically, these are the arguments
     *                                     to the Java function which performs the FS operation. The NameNode will
     *                                     extract these after it sees what function it is supposed to execute. These
     *                                     would traditionally just be passed as arguments to the RPC call, but we
     *                                     aren't using RPC.
     * @param requestId The unique ID used to match this request uniquely against its corresponding TCP request. If
     *                  passed a null, then a random ID is generated.
     * @param targetDeployment Specify the deployment to target. Use -1 to use the cache or a random deployment if no
     *                         cache entry exists.
     * @param subtreeOperation If true, use a longer timeout.
     *
     * @return An instance of {@link ServerlessHttpFuture}, which will eventually be populated with the response from
     * the Serverless NameNode that ultimately received the HTTP request.
     */
    public abstract ServerlessHttpFuture enqueueHttpRequest(String operationName, String functionUriBase,
                                                            HashMap<String, Object> nameNodeArguments,
                                                            ArgumentContainer fileSystemOperationArguments,
                                                            String requestId, int targetDeployment,
                                                            boolean subtreeOperation)
            throws IOException, IllegalStateException;

    /**
     * This is the internal API for enqueuing an HTTP request for submission. Requests are invoked asynchronously
     * and in a batched manner, meaning individual requests to the same deployment are batched together into larger
     * requests. The number of individual requests in a batch is configurable. Each batch of requests is delivered
     * to a single NameNode for processing.
     *
     * @param operationName The FS operation being performed.
     * @param nameNodeArguments Arguments for the Name Node itself. These would traditionally be passed as command line
     *                          arguments when using a serverful name node.
     * @param fileSystemOperationArguments The parameters to the FS operation. Specifically, these are the arguments
     *                                     to the Java function which performs the FS operation.
     * @param requestId The unique ID used to match this request uniquely against its corresponding TCP request. If
     *                  passed a null, then a random ID is generated.
     * @param targetDeployment Specify the deployment to target. Use -1 to use the cache or a random deployment if no
     *                         cache entry exists.
     * @param subtreeOperation If true, use a longer timeout as subtree operations can take a long time.
     *
     * @return An instance of {@link ServerlessHttpFuture}, which will eventually be populated with the response from
     * the Serverless NameNode that ultimately received the HTTP request.
     */
    protected ServerlessHttpFuture enqueueHttpRequestInt(String operationName,
                                                         JsonObject nameNodeArguments,
                                                         JsonObject fileSystemOperationArguments,
                                                         String requestId, int targetDeployment,
                                                         boolean subtreeOperation)
            throws IllegalStateException {
        if (!hasBeenConfigured())
            throw new IllegalStateException("Serverless Invoker has not yet been configured! " +
                    "You must configure it by calling .setConfiguration(...) before using it.");

        if (LOG.isDebugEnabled()) LOG.debug("Creating and enqueuing request " + requestId + "(op=" + operationName + ") targeting deployment " + targetDeployment);

        // We pass the file system operation arguments to the NameNode, as it
        // will hand them off to the intended file system operation function.
        nameNodeArguments.add(ServerlessNameNodeKeys.FILE_SYSTEM_OP_ARGS, fileSystemOperationArguments);
        nameNodeArguments.addProperty(ServerlessNameNodeKeys.OPERATION, operationName);
        nameNodeArguments.addProperty(ServerlessNameNodeKeys.CLIENT_NAME, clientName);
        nameNodeArguments.addProperty(ServerlessNameNodeKeys.IS_CLIENT_INVOKER, isClientInvoker);
        nameNodeArguments.addProperty(ServerlessNameNodeKeys.INVOKER_IDENTITY, invokerIdentity);
        nameNodeArguments.addProperty(REQUEST_ID, requestId);

        // TODO: Eventually switch this to trace rather than debug.
        if (LOG.isDebugEnabled()) LOG.debug("Enqueuing HTTP request " + requestId +
                " for submission with deployment " + targetDeployment);
        enqueueRequest(nameNodeArguments, targetDeployment);

        if (subtreeOperation) {
            LOG.info("Recording that request " + requestId + " is a subtree operation.");
            subtreeRequests.add(requestId);
        }

        ServerlessHttpFuture future = new ServerlessHttpFuture(requestId, operationName);
        futures.put(requestId, future);
        return future;
    }

    /**
     * Mark a particular request as complete. This just amounts to remove the future associated with the request from
     * the future mapping. This should be called by clients once they've received a correct result for their request.
     *
     * @param requestId the request ID of the request we're marking as complete.
     */
    public void markComplete(String requestId) {
        futures.remove(requestId);
    }

    /**
     * Helper function to issue an HTTP request with retries. This is how HTTP requests should be issued, as it
     * provides for exception handling and exponential backoff for retries.
     *
     * @param invokerInstance The {@link ServerlessInvokerBase} class to use to invoke the serverless function.
     * @param operationName The FS operation being performed. This is passed to the NameNode so that it knows which of
     *                      its functions it should execute. This is sort of taking the place of the RPC mechanism,
     *                      where ordinarily you'd just invoke an RPC method.
     * @param functionUriBase The base URI of the serverless function. We issue an HTTP request to this URI
     *                        in order to invoke the function. Before the request is issued, a number is appended
     *                        to the end of the URI to target a particular serverless name node. After the number is
     *                        appended, we also append a string ?blocking=true to ensure that the operation blocks
     *                        until it is completed so that the result may be returned to the caller.
     * @param nameNodeArguments Arguments for the Name Node itself. These would traditionally be passed as command line
     *                          arguments when using a serverful name node. We generally don't need to pass anything
     *                          for this parameter.
     * @param fileSystemOperationArguments The parameters to the FS operation. Specifically, these are the arguments
     *                                     to the Java function which performs the FS operation. The NameNode will
     *                                     extract these after it sees what function it is supposed to execute. These
     *                                     would traditionally just be passed as arguments to the RPC call, but we
     *                                     aren't using RPC.
     * @param requestId The unique ID used to match this request uniquely against its corresponding TCP request. If
     *                  passed a null, then a random ID is generated.
     * @param targetDeployment Specify the deployment to target. Use -1 to use the cache or a random deployment if no
     *                         cache entry exists.
     * @param subtreeOperation If this is a subtree operation, then the timeout needs to be adjusted.
     * @return The response from the Serverless NameNode.
     */
    public static JsonObject issueHttpRequestWithRetries(ServerlessInvokerBase invokerInstance, String operationName,
                                                   String functionUriBase, HashMap<String, Object> nameNodeArguments,
                                                   ArgumentContainer fileSystemOperationArguments,
                                                   String requestId, int targetDeployment, boolean subtreeOperation)
            throws IOException {
        long invokeStart = System.nanoTime();

        if (targetDeployment == -1)
            targetDeployment = rng.nextInt(invokerInstance.numDeployments);

        ExponentialBackOff exponentialBackoff = new ExponentialBackOff.Builder()
                .setMaximumRetries(invokerInstance.maxHttpRetries)
                .setInitialIntervalMillis(10000)
                .setMaximumIntervalMillis(30000)
                .setMultiplier(2.25)
                .setRandomizationFactor(0.5)
                .build();

//        if (LOG.isTraceEnabled()) {
//            double timeElapsed = (System.nanoTime() - invokeStart) / 1.0e6;
//            LOG.trace("Issuing HTTP request " + requestId + " to deployment " + targetDeployment + ", attempt " +
//                    (exponentialBackoff.getNumberOfRetries()+1) + "/" + invokerInstance.maxHttpRetries +
//                    ". Time elapsed: " + timeElapsed + " milliseconds.");
//        } else if (LOG.isDebugEnabled()) {
//            LOG.debug("Issuing HTTP request " + requestId + " to deployment " + targetDeployment + ", attempt " +
//                    (exponentialBackoff.getNumberOfRetries()+1) + "/" + invokerInstance.maxHttpRetries + ".");
//        }
        if (LOG.isDebugEnabled())
            LOG.debug("Issuing HTTP request " + requestId + " to deployment " + targetDeployment + ", attempt " +
                    (exponentialBackoff.getNumberOfRetries()+1) + "/" + invokerInstance.maxHttpRetries + ".");

        long backoffInterval = exponentialBackoff.getBackOffInMillis();

        do {
            ServerlessHttpFuture future = invokerInstance.enqueueHttpRequest(operationName, functionUriBase,
                    nameNodeArguments, fileSystemOperationArguments, requestId, targetDeployment, subtreeOperation);

            JsonObject response;
            try {
                response = future.get();
            } catch (InterruptedException | ExecutionException ex) {
                LOG.error("Exception encountered while waiting on Future for HTTP request...");
                LOG.warn("Sleeping for " + backoffInterval + " milliseconds before trying again...");
                invokerInstance.doSleep(backoffInterval);
                backoffInterval = exponentialBackoff.getBackOffInMillis();
                continue;
            }

            if (response.has(LOCAL_EXCEPTION)) {
                String genericExceptionType = response.get(LOCAL_EXCEPTION).getAsString();

                if (genericExceptionType.equalsIgnoreCase("NoHttpResponseException") ||
                        genericExceptionType.equalsIgnoreCase("SocketTimeoutException")) {
                    double timeElapsed = (System.nanoTime() - invokeStart) / 1000000.0;
                    LOG.error("Attempt " + (exponentialBackoff.getNumberOfRetries()) +
                            " to issue request targeting deployment " + targetDeployment +
                            " timed out. Time elapsed: " + timeElapsed + " ms.");
                    LOG.warn("Sleeping for " + backoffInterval + " milliseconds before trying again...");
                    invokerInstance.doSleep(backoffInterval);
                    backoffInterval = exponentialBackoff.getBackOffInMillis();
                }
                else if (genericExceptionType.equalsIgnoreCase("IOException")) {
                    LOG.error("Encountered IOException while invoking NN via HTTP.");
                    LOG.warn("Sleeping for " + backoffInterval + " milliseconds before trying again...");
                    invokerInstance.doSleep(backoffInterval);
                    backoffInterval = exponentialBackoff.getBackOffInMillis();
                } else {
                    LOG.error("Unexpected error encountered while invoking NN via HTTP: " + genericExceptionType);
                    throw new IOException("The file system operation could not be completed. "
                            + "Encountered unexpected " + genericExceptionType + " while invoking NN.");
                }
            } else {
                // Received a valid result. Return it to the client.
                // First though, we should mark the request as complete.
                invokerInstance.markComplete(requestId);
                return response;
            }
        } while (backoffInterval > 0);

        throw new IOException("The file system operation could not be completed. " +
                "Failed to invoke Serverless NameNode " + targetDeployment + " after " +
                invokerInstance.maxHttpRetries + " attempts.");
    }

    /**
     * Package up a batch of requests and send them to the target deployment via an HTTP request.
     *
     * @param requestBatch The batch of requests we're sending.
     * @param requestUri The HTTP endpoint of the target deployment.
     * @param authorizationString Included with the request. Used for authorizing the request.
     */
    protected void prepareAndInvokeRequestBatch(JsonObject requestBatch, String requestUri, String authorizationString)
            throws SocketException, UnknownHostException, UnsupportedEncodingException {
        // This is the top-level JSON object passed along with the HTTP POST request.
        JsonObject topLevel = new JsonObject();
        HttpPost request = new HttpPost(requestUri);
        request.setHeader(HttpHeaders.AUTHORIZATION, "Basic " + authorizationString);

        // Check if the batch has a flag on it indicating that it contains a subtree operation.
        if (requestBatch.has(CONTAINS_SUBTREE_OP)) {
            // Remove the flag so that it doesn't get confused as being an actual request.
            requestBatch.remove(CONTAINS_SUBTREE_OP);

            request.setConfig(RequestConfig
                    .custom()
                    .setConnectTimeout(httpTimeoutMilliseconds)
                    .setConnectionRequestTimeout(httpTimeoutMilliseconds)
                    .setSocketTimeout(720000) // 12 minutes.
                    .build());

            LOG.info("Configuring HTTP request containing at least one subtree operation with extended socket timeout.");
        }

        JsonObject nameNodeArguments = new JsonObject();
        nameNodeArguments.add(BATCH, requestBatch);
        addStandardArguments(nameNodeArguments);

        // OpenWhisk expects the arguments for the serverless function handler to be included in the JSON contained
        // within the HTTP POST request. They should be included with the key "value".
        topLevel.add(ServerlessNameNodeKeys.VALUE, nameNodeArguments);

        // String requestUri = getFunctionUri(functionUriBase, i, topLevel);

        // Prepare the HTTP POST request.
        StringEntity parameters = new StringEntity(topLevel.toString());
        request.setEntity(parameters);
        request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");

        try {
            doInvoke(request, topLevel, requestBatch.keySet());
        } catch (IOException ex) {
            LOG.error("Encountered IOException while issuing batched HTTP request:", ex);
        }
    }

    /**
     * Asynchronously invoke a batched HTTP request.
     *
     * @param request The HTTP request to invoke. This is the actual HTTP request object itself.
     * @param requestArguments This presumably contains a batch of multiple individual requests
     *                         that will all be processed by the same NameNode.
     * @param requestIds The IDs of the individual requests contained within the batch.
     */
    protected void doInvoke(HttpPost request, JsonObject requestArguments, Set<String> requestIds)
            throws IOException {
        final long invokeStart = System.currentTimeMillis();

        // Prepare the HTTP POST request.
        StringEntity parameters = new StringEntity(requestArguments.toString());
        request.setEntity(parameters);
        request.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing batched request containing " + requestIds.size() + " individual request(s): " +
                    StringUtils.join(", ", requestIds));
        }

        // Future<HttpResponse> future =
        httpClient.execute(request, new FutureCallback<HttpResponse>() {
            @Override
            public void completed(HttpResponse httpResponse) {
                int responseCode = httpResponse.getStatusLine().getStatusCode();

                if (LOG.isDebugEnabled()) {
                    long currentTime = System.nanoTime();
                    double timeElapsed = (currentTime - invokeStart) / 1.0e6;
                    LOG.debug("Received HTTP " + responseCode +
                            " response code. Time elapsed: " + timeElapsed + " milliseconds.");
                    LOG.debug("httpResponse = " + httpResponse);
                }

                if (responseCode >= 400 && responseCode <= 599) {
                    LOG.error("Received HTTP response code " + responseCode +
                            " for batched HTTP request containing " + requestIds.size() +
                            " individual requests. Request IDs: " + StringUtils.join(", ", requestIds));

                    // For each of the individual requests in the batch, post an error message to the future.
                    // This way, the client can be notified of the failure and retry the request if desired.
                    for (String requestId : requestIds) {
                        ServerlessHttpFuture future = futures.get(requestId);
                        JsonObject response = new JsonObject();
                        response.addProperty("EXCEPTION_TYPE", "HttpResponseCode" + responseCode);
                        future.postResultImmediate(response);
                    }

                    return;
                }

                try {
                    // Extract the payload from the HTTP response.
                    JsonObject httpResponseAsJson = processHttpResponse(httpResponse);

                    LOG.debug("JsonObject response from HTTP request: " + httpResponseAsJson);

                    JsonObject result;
                    if (httpResponseAsJson.has("body"))
                        result = httpResponseAsJson.get("body").getAsJsonObject();
                    else
                        result = httpResponseAsJson;

                    // For each of the individual requests in the batch, post an error message to the future.
                    // This way, the client can be notified of the failure and retry the request if desired.
                    Set<String> requestIds = result.keySet();
                    if (LOG.isDebugEnabled()) LOG.debug("Received batch of " + requestIds.size() + " result(s).");
                    for (String requestId : requestIds) {
                        if (LOG.isDebugEnabled()) LOG.debug("Received result for HTTP request " + requestId);
                        ServerlessHttpFuture future = futures.get(requestId);
                        future.postResultImmediate(result.get(requestId).getAsJsonObject());
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    request.releaseConnection();
                }
            }

            @Override
            public void failed(Exception e) {
                LOG.error("Batched HTTP request containing " + requestIds.size() +
                        " individual request(s) has failed. Request IDs: " +
                        StringUtils.join(", ", requestIds) + ". Reason for failure:", e);

                for (String requestId : requestIds) {
                    ServerlessHttpFuture future = futures.get(requestId);

                    if (future == null) {
                        LOG.error("Cannot locate Future for request " + requestId + "...");
                        continue;
                    }

                    JsonObject response = new JsonObject();

                    if (e != null)
                        response.addProperty(LOCAL_EXCEPTION, e.getClass().getSimpleName());
                    else
                        response.addProperty(LOCAL_EXCEPTION, "GENERIC/UNKNOWN");

                    future.postResultImmediate(response);
                }
            }

            @Override
            public void cancelled() {
                LOG.warn("HTTP request has been cancelled.");
                request.releaseConnection();
            }
        });

//        LOG.debug("Getting response from Future<HttpResponse> now...");
//        try {
//            HttpResponse response = future.get();
//            JsonObject result = processHttpResponse(response);
//            LOG.debug("Got HttpResponse: " + result);
//        } catch (InterruptedException | ExecutionException e) {
//            e.printStackTrace();
//        }
    }

    /**
     * Return an HTTP client that could theoretically be used for any platform. This client trusts all certificates,
     * so it is insecure.
     */
    public CloseableHttpAsyncClient getGenericTrustAllHttpClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, IOReactorException {
//        if (LOG.isDebugEnabled()) {
//            LOG.debug("Setting HTTP connection timeout to " + httpTimeoutMilliseconds + " milliseconds.");
//            LOG.debug("Setting HTTP socket timeout to " + httpTimeoutMilliseconds + " milliseconds.");
//        }

        RequestConfig requestConfig = RequestConfig
                .custom()
                .setConnectTimeout(httpTimeoutMilliseconds)
                .setSocketTimeout(httpTimeoutMilliseconds)
                .setConnectionRequestTimeout(httpTimeoutMilliseconds)
                .build();

        // This allows us to issue multiple HTTP requests at once, which may or may not be desirable/useful...
        // Like, I'm not sure if that's something we'll do within the same process/thread.

        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        //LOG.debug("getAcceptedIssuers() called!");
                        return new X509Certificate[0];
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        //LOG.debug("checkClientTrusted() called!");
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        //LOG.debug("checkServerTrusted() called!");
                    }
                }
        };

        TrustStrategy acceptingTrustStrategy = (x509Certificates, s) -> true;
        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        // SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());

        SSLIOSessionStrategy sslioSessionStrategy =
                new SSLIOSessionStrategy(sslContext, null, null, new NoopHostnameVerifier());

        Registry<SchemeIOSessionStrategy> socketFactoryRegistry = RegistryBuilder
                .<SchemeIOSessionStrategy>create()
                .register("https", sslioSessionStrategy)
                .register("http", NoopIOSessionStrategy.INSTANCE)
                .build();

        IOReactorConfig ioReactorConfig = IOReactorConfig.custom()
                .setSelectInterval(Math.max(httpTimeoutMilliseconds / 10, 1000)) // Default is 1000
                // .setSoTimeout(httpTimeoutMilliseconds)
                .setConnectTimeout(httpTimeoutMilliseconds)
                .build();

        // Need to pass registry to this type of connection manager, as custom SSLContext is ignored.
        PoolingNHttpClientConnectionManager connectionManager =
                new PoolingNHttpClientConnectionManager(new DefaultConnectingIOReactor(ioReactorConfig), socketFactoryRegistry);
        connectionManager.setMaxTotal(50);
        connectionManager.setDefaultMaxPerRoute(50);

        return HttpAsyncClients
                .custom()
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                //.setSSLSocketFactory(csf)
                .setSSLContext(sslContext)
                .setDefaultRequestConfig(requestConfig)
                .setConnectionManager(connectionManager)
                .build();
    }

    /**
     * Get an HTTP client configured for the particular serverless platform.
     */
    public abstract CloseableHttpAsyncClient getHttpClient()
            throws NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException, IOReactorException;

    /**
     * Extract the result of a file system operation from the {@link JsonObject} returned by the NameNode.
     * @param resp The response from the NameNode.
     * @return The result contained within the JsonObject returned by the NameNode.
     */
    public Object extractResultFromJsonResponse(JsonObject resp) {
        JsonObject response = resp;

        // TODO: This might happen if all requests to a NN time out, in which case we should either handle
        //       it more cleanly and/or throw a more meaningful exception.
        if (response == null) {
            throw new IllegalStateException(
                    "Response from serverless NameNode was null. Perhaps all request attempts timed out...");
        }

        // Sometimes(?) the actual result is included in the "body" key.
        if (response.has("body"))
            response = resp.get("body").getAsJsonObject();

        String requestId;
        if (response.has(REQUEST_ID))
            requestId = response.getAsJsonPrimitive(REQUEST_ID).getAsString();
        else
            requestId = "N/A";

        // First, let's check and see if there's any information about file/directory-to-function mappings.
//        if (response.has(ServerlessNameNodeKeys.DEPLOYMENT_MAPPING) && cache != null) {
//            JsonObject functionMapping = response.getAsJsonObject(ServerlessNameNodeKeys.DEPLOYMENT_MAPPING);
//
//            String src = functionMapping.getAsJsonPrimitive(ServerlessNameNodeKeys.FILE_OR_DIR).getAsString();
//            long parentINodeId = functionMapping.getAsJsonPrimitive(ServerlessNameNodeKeys.PARENT_ID).getAsLong();
//            int function = functionMapping.getAsJsonPrimitive(ServerlessNameNodeKeys.FUNCTION).getAsInt();
//
//            // cache.addEntry(src, function, false);
//        }

        // Print any exceptions that were encountered first.
        if (response.has(ServerlessNameNodeKeys.EXCEPTIONS)) {
            JsonArray exceptionsJson = response.get(ServerlessNameNodeKeys.EXCEPTIONS).getAsJsonArray();

            int numExceptions = exceptionsJson.size();

            if (numExceptions > 0) {
                LOG.warn("=+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=");
                LOG.warn("*** The ServerlessNameNode encountered " + numExceptions +
                        (numExceptions == 1 ? " exception. ***" : " exceptions. ***"));

                for (int i = 0; i < exceptionsJson.size(); i++)
                    LOG.error(exceptionsJson.get(i).getAsString());
                LOG.warn("=+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=+==+=");
            }
        }

        // This is just related to debugging/metrics. There are objects called "STATISTICS PACKAGES" that have
        // certain statistics about NN execution. We're just checking if there are any included here and, if so,
        // then we extract them.
        if (response.has(ServerlessNameNodeKeys.STATISTICS_PACKAGE)) {
            String statisticsPackageEncoded =
                    response.getAsJsonPrimitive(ServerlessNameNodeKeys.STATISTICS_PACKAGE).getAsString();

            try {
                TransactionsStats.ServerlessStatisticsPackage statisticsPackage =
                        (TransactionsStats.ServerlessStatisticsPackage)
                                InvokerUtilities.base64StringToObject(statisticsPackageEncoded);
                statisticsPackages.put(requestId, statisticsPackage);
            } catch (Exception ex) {
                LOG.error("Error encountered while extracting statistics packages from NameNode response:", ex);
                return null;
            }
        }

        // Similar to "STATISTICS PACKAGES". See comment above.
        if (response.has(ServerlessNameNodeKeys.TRANSACTION_EVENTS)) {
            String transactionEventsEncoded =
                    response.getAsJsonPrimitive(ServerlessNameNodeKeys.TRANSACTION_EVENTS).getAsString();

            try {
                List<TransactionEvent> txEvents =
                        (List<TransactionEvent>) InvokerUtilities.base64StringToObject(transactionEventsEncoded);
                transactionEvents.put(requestId, txEvents);
            } catch (Exception ex) {
                LOG.error("Error encountered while extracting transaction events from NameNode response:", ex);
                return null;
            }
        }

        // Now we'll check for a result from the name node.
        if (response.has(ServerlessNameNodeKeys.RESULT)) {
            String resultBase64 = response.getAsJsonPrimitive(ServerlessNameNodeKeys.RESULT).getAsString();

            try {
                Object result = InvokerUtilities.base64StringToObject(resultBase64);

                if (result == null || (result instanceof NullResult)) {
                    return null;
                }

                if (LOG.isTraceEnabled())
                    LOG.trace("Returning object of type " + result.getClass().getSimpleName() + ": " + result);
                return result;
            } catch (Exception ex) {
                LOG.error("Error encountered while extracting result from NameNode response:", ex);
                return null;
            }
        }

        return null;
    }

    /**
     * Set the name of the client using this invoker (e.g., the `clientName` field of the DFSClient class).
     * @param clientName the name of the client (e.g., the `clientName` field of the DFSClient class).
     */
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    /**
     * Calls the `terminate()` function of the "INode mapping" cache.
     */
    public void terminate() {
        // cache.terminate();
    }

    /**
     * Sets the flag indicating whether this Invoker is used by a client/user.
     *
     * DataNodes and NameNodes only use HTTP to talk to other NameNodes.
     * DataNodes could theoretically use TCP, but for now, they don't.
     *
     * True indicates client/user, false indicates datanode.
     */
    public void setIsClientInvoker(boolean isClientInvoker) {
        this.isClientInvoker = isClientInvoker;

        // DataNodes and NameNodes only use HTTP to talk to other NameNodes.
        // DataNodes could theoretically use TCP, but for now, they don't.
        if (!isClientInvoker)
            this.tcpEnabled = false;
    }

    /**
     * Returns True if this invoker has already been configured via the `setConfiguration()` API.
     * Otherwise, returns false.
     */
    public boolean hasBeenConfigured() {
        return configured;
    }

    /**
     * Hide try-catch for Thread.sleep().
     * @param backoffInterval How long to sleep in milliseconds.
     */
    protected void doSleep(long backoffInterval) {
        try {
            Thread.sleep(backoffInterval);
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }
    }

    /**
     * There are some arguments that will be included every single time with the same values. This function
     * adds those arguments, thereby reducing the amount of boiler-plate code.
     *
     * This is implemented as a separate function to provide a centralized place to modify these
     * consistent arguments.
     *
     * The standard arguments are currently:
     *  - Command-line arguments for the NN (if none are provided already)
     *  - Request ID
     *  - Internal IP address of the node on which the client is running.
     *  - Flag indicating whether NDB debug logging should be enabled.
     *  - The NDB debug string that controls the format/content of the NDB debug logging.
     *  - Flag indicating whether TCP is enabled.
     *  - The TCP port that our TCP server is listening on.
     *  - Our internal IP address.
     *  - Flag indicating whether the NameNode is running in local mode.
     *
     * @param nameNodeArgumentsJson The arguments to be passed to the ServerlessNameNode itself.
     */
    protected void addStandardArguments(JsonObject nameNodeArgumentsJson)
            throws SocketException, UnknownHostException {
        // If there is not already a command-line-arguments entry, then we'll add one with the "-regular" flag
        // so that the name node performs standard execution. If there already is such an entry, then we do
        // not want to overwrite it.
        if (!nameNodeArgumentsJson.has(COMMAND_LINE_ARGS))
            nameNodeArgumentsJson.addProperty(COMMAND_LINE_ARGS, "-regular");

        // If TCP is enabled, then we'll add the TCP (and possibly UDP) ports to the arguments.
        if (this.tcpEnabled) {
            if (this.tcpPort == 0)
                throw new IllegalStateException("TCP Port has not been initialized to correct value.");

            JsonArray tcpPortsJson = new JsonArray();
            List<Integer> tcpPorts = ServerAndInvokerManager.getInstance().getActiveTcpPorts();
            for (int tcpPort : tcpPorts)
                tcpPortsJson.add(tcpPort);

            JsonArray udpPortsJson = new JsonArray();
            List<Integer> udpPorts = udpEnabled ?
                    ServerAndInvokerManager.getInstance().getActiveUdpPorts() : new ArrayList<>();
            for (int udpPort : udpPorts)
                udpPortsJson.add(udpPort);

            nameNodeArgumentsJson.add(TCP_PORT, tcpPortsJson);
            nameNodeArgumentsJson.add(UDP_PORT, udpPortsJson);
        }

        // nameNodeArgumentsJson.addProperty(REQUEST_ID, requestId);
        nameNodeArgumentsJson.addProperty(DEBUG_NDB, debugEnabledNdb);
        nameNodeArgumentsJson.addProperty(DEBUG_STRING_NDB, debugStringNdb);
        nameNodeArgumentsJson.addProperty(BENCHMARK_MODE, benchmarkModeEnabled);

        // If we aren't a client invoker (e.g., DataNode, other NameNode, etc.), then don't populate the internal IP field.
        nameNodeArgumentsJson.addProperty(CLIENT_INTERNAL_IP, (isClientInvoker ? InvokerUtilities.getInternalIpAddress() : "0.0.0.0"));

        nameNodeArgumentsJson.addProperty(TCP_ENABLED, tcpEnabled);
        nameNodeArgumentsJson.addProperty(UDP_ENABLED, udpEnabled);
        nameNodeArgumentsJson.addProperty(LOCAL_MODE, localMode);
        nameNodeArgumentsJson.addProperty(CONSISTENCY_PROTOCOL_ENABLED, consistencyProtocolEnabled);
        nameNodeArgumentsJson.addProperty(LOG_LEVEL, OpenWhiskHandler.getLogLevelIntFromString(serverlessFunctionLogLevel));
    }

    ///////////////////////
    // DEBUGGING/METRICS //
    ///////////////////////

    public static ConcurrentHashMap<String, TransactionsStats.ServerlessStatisticsPackage> getStatisticsPackages() {
        return statisticsPackages;
    }

    public static void setStatisticsPackages(ConcurrentHashMap<String, TransactionsStats.ServerlessStatisticsPackage> packages) {
        statisticsPackages = packages;
    }

    public static ConcurrentHashMap<String, List<TransactionEvent>> getTransactionEvents() {
        return transactionEvents;
    }

    public static void setTransactionEvents(ConcurrentHashMap<String, List<TransactionEvent>> txEvents) {
        transactionEvents = txEvents;
    }

    public static void clearStatisticsPackages() {
        statisticsPackages.clear();
    }

    public static void clearTransactionEvents() {
        transactionEvents.clear();
    }
}
