package net.floodlightcontroller.unipi.maliciousflows.model;

import java.lang.reflect.Array;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Class used to implement a circular buffer which can change size on demand
*/
public class QuarantineBuffer<T> {

    private final AtomicInteger cursor = new AtomicInteger(0);
    private Object[] buffer;
    private final Class<T> type;

    public QuarantineBuffer(final int bufferSize, final Class<T> type) {
        if (bufferSize < 1) 
            throw new IllegalArgumentException("Buffer size must be a positive value");
            
        this.type = type;
        this.buffer = new Object[bufferSize];
    }

    /**
     * mehod used to add element
     * @param sample element to be add
     */
    public void add(T sample) {
        // circular buffer
        buffer[cursor.getAndIncrement() % buffer.length] = sample;
    }

    /**
     * Method used to change the size of the buffer, if the size is reducede
     * you may lost the last added elements
     * @param newBufferSize new buffer length
     */
    public void changeBufferSize(int newBufferSize) {
        // check if the size is greater than zero
        if (newBufferSize < 1) 
            throw new IllegalArgumentException("Buffer size must be a positive value");

        // special case where the array is empty
        if (cursor.get() == 0) {
            buffer = new Object[newBufferSize];
        }

        // new buffer
        Object[] newBuffer = new Object[newBufferSize];
        
        // check if we are increasing or reducing size
        if (buffer.length >= newBufferSize) {
            // we are reducing the size of the buffer, we may have to drop the oldest packets
            if (cursor.get() > buffer.length) {
                // we have overwrite some packets
                int start = cursor.get() - newBufferSize;
                for (int i = start; i < cursor.get(); i++) {
                    newBuffer[i % newBufferSize] = buffer[i % buffer.length]; 
                }
            } else {
                int start = cursor.get() - newBufferSize;
                if (start < 0) start = 0;
                for (int i = start; i < cursor.get(); i++) {
                    newBuffer[i % newBufferSize] = buffer[i]; 
                }
            }
        } else {
            // we are increasing the size of the buffer
            if (cursor.get() < buffer.length) {
                // I have not overwrite elements, so we can directly copy everything
                System.arraycopy(buffer, 0, newBuffer, 0, cursor.get());
            } else {
                // we have overwrite few elemets so we have to pay attention
                int split = cursor.get() % buffer.length;
                int diff = newBufferSize - buffer.length;
                System.arraycopy(buffer, 0, newBuffer, 0, split);
                System.arraycopy(buffer, split, newBuffer, split + diff, newBufferSize - split - diff);
                // adjust the cursor
                int newCursor = (cursor.get() % buffer.length) + newBufferSize;
                cursor.set(newCursor);
            }
        }
        buffer = newBuffer;
        return;
    }

    /**
     * method used to get the buffer size
     * @return buffer size
     */
    public int getBufferSize() {
        return buffer.length;
    }

    /**
     * method used to get the number of elements stored in the buffer
     * @return number
     */
    public int getNumberOfStoredObjects() {
        if (cursor.get() >= buffer.length)
            return buffer.length;
        return cursor.get();
    }

    /**
     * method used to retrieve all the element in the buffer
     * @return list of elements
     */
    @SuppressWarnings("unchecked")
    public T[] getContents() {
        if (cursor.get() == 0) {
            return (T[]) Array.newInstance(type, 0);
        }

        int size = cursor.get() < buffer.length ? cursor.get() : buffer.length;
        T[] result = (T[]) Array.newInstance(type, size);

        System.arraycopy(buffer, 0, result, 0, size);

        return (T[]) result;
    }

}
