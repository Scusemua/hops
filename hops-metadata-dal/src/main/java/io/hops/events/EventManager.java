package io.hops.events;

import io.hops.exception.StorageException;

/**
 * Generic interface defining the API of the EventManager.
 *
 * This interface is specifically designed to be used with MySQL Cluster NDB, but theoretically
 * this interface could be implemented to work with Redis (for example).
 *
 * Concrete implementations of this class are expected to interface with some sort of caching mechanism. This
 * caching mechanism is responsible for managing the cache on the NameNode.
 *
 * The EventManager simply informs the cache that its data is out of date (i.e., it has been invalidated), and thus
 * it must be updated.
 *
 * The EventManager is expected to run as its own thread so that listening for events does not block other threads.
 * As such, it extends Runnable so that subclasses implement their own Run method.
 */
public interface EventManager extends Runnable {
    /**
     * Get the name of the event used to listen for changes to INodes in intermediate storage.
     *
     * TODO: This is not really generic...
     */
    public String getINodeEventName();

    /**
     * Get the name of the event used to listen for ACKs on the `write_acknowledgements` table.
     *
     * TODO: This is not really generic...
     */
    public String getAckTableEventName();

    /**
     * Get the event columns used in the INode table event.
     *
     * TODO: This is not really generic...
     */
    public String[] getINodeEventColumns();

    /**
     * Get the event columns used in the ACK table event.
     *
     * TODO: This is not really generic...
     */
    public String[] getAckTableEventColumns();

    /**
     * Create and register an event with the given name.
     * @param eventName Unique identifier of the event to be created.
     * @param recreateIfExists If true, delete and recreate the event if it already exists.
     * @throws StorageException if something goes wrong when registering the event.
     * @return True if an event was created, otherwise false.
     */
    public boolean registerEvent(String eventName, String tableName, boolean recreateIfExists) throws StorageException;

    /**
     * Delete the event with the given name.
     * @param eventName Unique identifier of the event to be deleted.
     * @return True if an event with the given name was deleted, otherwise false.
     *
     * @throws StorageException if something goes wrong when unregistering the event.
     */
    public boolean unregisterEvent(String eventName) throws StorageException;

    /**
     * Listen for events.
     */
    @Override
    public void run();

    /**
     * Create and register an Event Operation for the specified event.
     *
     * @param eventName The name of the Event for which we're creating an EventOperation.
     */
    public void createEventOperation(String eventName) throws StorageException;

    /**
     * Perform the default setup/initialization of the event and event operation.
     * @param eventName The name of the event to create/look for.
     * @param deleteIfExists Delete and recreate the event, if it already exists.
     */
    public void defaultSetup(String eventName, boolean deleteIfExists) throws StorageException;

    /**
     * Unregister and drop the EventOperation associated with the given event from NDB.
     * @param eventName The unique identifier of the event whose EventOperation we wish to unregister.
     * @return True if an event operation was dropped, otherwise false.
     */
    public boolean unregisterEventOperation(String eventName) throws StorageException;

    /**
     * This should be called once it is known that there are events to be processed.
     * @return the number of events that were processed.
     */
    public int processEvents();

    /**
     * Register an event listener with the event manager.
     *
     * @param listener the event listener to be registered.
     * @param eventName the name of the event for which we're registering an event listener.
     */
    public void addListener(HopsEventListener listener, String eventName);

    /**
     * Unregister an event listener with the event manager.
     * @param listener the event listener to be unregistered.
     * @param eventName the name of the event for which we're unregistering an event listener.
     *
     * @throws IllegalArgumentException If we do not have the provided listener registered with the specified event.
     */
    public void removeListener(HopsEventListener listener, String eventName);
}
