package com.alibaba.nacos.client.aliyun;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author rong
 */
public class AsyncProcessor {

    private static final int QUEUE_INITIAL_CAPACITY = 8;

    private static final String DEFAULT_PROCESSOR_NAME = "asyncProcessor";

    private static final Logger LOGGER = LoggerFactory.getLogger(AsyncProcessor.class);

    private final BlockingQueue<Runnable> queue;

    private final AtomicBoolean closed;

    private final String name;

    public AsyncProcessor() {
        this(QUEUE_INITIAL_CAPACITY, DEFAULT_PROCESSOR_NAME);
    }

    public AsyncProcessor(int queueSize, String name) {
        this.queue = new ArrayBlockingQueue<Runnable>(queueSize);
        this.closed = new AtomicBoolean(false);
        this.name = name;
        (new InnerWorker(name)).start();
    }

    public void addTack(Runnable task) {
        try {
            queue.put(task);
        } catch (InterruptedException e) {
            LOGGER.error(e.toString(), e);
        }
    }

    public void shutdown() {
        queue.clear();
        closed.compareAndSet(false, true);
    }

    public String getName() {
        return name;
    }

    private class InnerWorker extends Thread {
        InnerWorker(String name) {
            super(name);
        }
        @Override
        public void run() {
            while (!closed.get()) {
                try {
                    Runnable task = queue.take();
                    long begin = System.currentTimeMillis();
                    task.run();
                    long duration = System.currentTimeMillis();
                    LOGGER.info("runner[{}] executed task {} cost {} ms", getName(), task, duration - begin);
                } catch (Exception e) {
                    LOGGER.error(e.toString(), e);
                }
            }
        }
    }
}
