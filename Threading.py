import time
from queue import Queue, Empty
from threading import Thread


def producer(queue):
    for i in range(1, 6):
        print("Inserting {} into the queue".format(i))
        time.sleep(1)
        queue.put(i)


def consumer(queue):
    while True:
        try:
            item = queue.get()
        except Empty:
            continue
        else:
            print("Processing item {}".format(item))
            time.sleep(2)
            queue.task_done()


def main():
    queue = Queue()

    # create a producer thread and start it
    producer_thread = Thread(target=producer, args=(queue,))
    producer_thread.start()

    # create a consumer thread and start it
    consumer_thread = Thread(target=consumer, args=(queue,), daemon=True)
    consumer_thread.start()

    # wait for all tasks to be added to the queue
    producer_thread.join()

    # wait for all tasks on the queue to be completed
    queue.join()


if __name__ == "__main__":
    main()
