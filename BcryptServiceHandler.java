import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.mindrot.jbcrypt.BCrypt;

public class BcryptServiceHandler implements BcryptService.Iface
{
	private List<BlockingQueue<BcryptServiceBE.Client>> backendServerPool = new ArrayList<>(2);
	private AtomicInteger roundRobin = new AtomicInteger(0);

	public List<String> hashPassword(List<String> password, short logRounds) throws IllegalArgument, org.apache.thrift.TException
	{
		int numPass = password.size();
		int numBE = backendServerPool.size();
		List<String> ret = new ArrayList<>(numPass);
		try {
			//Only 1 client (split)
			if (numPass == 16) {
				//Split strings even between BE + FE
				if (numBE == 2) {
					//Start a job for both BEs
					ThreadedHashBE backendThread0 = new ThreadedHashBE(password.subList(10, 16), logRounds, backendServerPool.get(0).element());
					ThreadedHashBE backendThread1 = new ThreadedHashBE(password.subList(4, 10), logRounds, backendServerPool.get(1).element());
					Thread threadBE0 = new Thread(backendThread0);
					Thread threadBE1 = new Thread(backendThread1);
					threadBE0.start();
					threadBE1.start();

					//Start a job for both FE threads
					ThreadedHashFE frontendThread = new ThreadedHashFE(password.subList(2, 4), logRounds);
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 2; ++i) {
						String onePwd = password.get(i);
						String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
						ret.add(oneHash);
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);

					//Wait for BEs to finish
					threadBE0.join();
					threadBE1.join();

					//Add BE results.
					ret.addAll(backendThread1.retBE);
					ret.addAll(backendThread0.retBE);
				}
				else if (numBE == 1) {
					//Start a job for one BE
					ThreadedHashBE backendThread = new ThreadedHashBE(password.subList(8, 16), logRounds, backendServerPool.get(0).element());
					Thread threadBE = new Thread(backendThread);
					threadBE.start();

					//Start a job for both FE threads
					ThreadedHashFE frontendThread = new ThreadedHashFE(password.subList(4, 8), logRounds);
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 4; ++i) {
						String onePwd = password.get(i);
						String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
						ret.add(oneHash);
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);

					//Wait for BE to finish
					threadBE.join();

					//Add BE results.
					ret.addAll(backendThread.retBE);
				}
				else {
					//Start a job for both FE threads
					ThreadedHashFE frontendThread = new ThreadedHashFE(password.subList(8, 16), logRounds);
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 8; ++i) {
						String onePwd = password.get(i);
						String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
						ret.add(oneHash);
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);
				}
			}
			//Multiple client (round robin + split)
			else if (numPass == 4) {
				int server = roundRobin.getAndIncrement() % (numBE + 1);
				//Start a job for both FE threads
				if (server == 0) {
					ThreadedHashFE frontendThread = new ThreadedHashFE(password.subList(2, 4), logRounds);
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 2; ++i) {
						String onePwd = password.get(i);
						String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
						ret.add(oneHash);
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);
				}
				//Start a job for one BE
				else {
					//Block until BE socket is available
					BcryptServiceBE.Client backendThread = backendServerPool.get(server - 1).take();
					List<String> hash = backendThread.hashPassword(password, logRounds);
					backendServerPool.get(server - 1).add(backendThread);
					ret.addAll(hash);
				}
			}
			//Multiple client (round robin)
			else {
				int server = roundRobin.getAndIncrement() % (numBE + 1);
				//Start a job for one FE thread
				if (server == 0) {
					String onePwd = password.get(0);
					String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
					ret.add(oneHash);
				}
				//Start a job for one BE
				else {
					//Block until BE socket is available
					BcryptServiceBE.Client backendThread = backendServerPool.get(server - 1).take();
					List<String> hash = backendThread.hashPassword(password, logRounds);
					backendServerPool.get(server - 1).add(backendThread);
					ret.addAll(hash);
				}
			}
			//Check for errors
			if (ret.size() != password.size()) throw new IllegalArgument();
			
			return ret;
		} catch (Exception e) {
			throw new IllegalArgument("Illegal logRounds");
		}
	}

	public List<Boolean> checkPassword(List<String> password, List<String> hash) throws IllegalArgument, org.apache.thrift.TException
	{
		int numPass = password.size();
		int numBE = backendServerPool.size();
		List<Boolean> ret = new ArrayList<>(numPass);

		if (numPass != hash.size()) throw new IllegalArgument("password.size() != hash.size()");
		try {
			//Only 1 client (split)
			if (numPass == 16) {
				//Split strings even between BE + FE
				if (numBE == 2) {
					//Start a job for both BEs
					ThreadedCheckBE backendThread0 = new ThreadedCheckBE(password.subList(10, 16), hash.subList(10, 16), backendServerPool.get(0).element());
					ThreadedCheckBE backendThread1 = new ThreadedCheckBE(password.subList(4, 10), hash.subList(4, 10), backendServerPool.get(1).element());
					Thread threadBE0 = new Thread(backendThread0);
					Thread threadBE1 = new Thread(backendThread1);
					threadBE0.start();
					threadBE1.start();

					//Start a job for both FE threads
					ThreadedCheckFE frontendThread = new ThreadedCheckFE(password.subList(2, 4), hash.subList(2, 4));
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 2; ++i) {
						String onePwd = password.get(i);
						String oneHash = hash.get(i);
						ret.add(BCrypt.checkpw(onePwd, oneHash));
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);

					//Wait for BEs to finish
					threadBE0.join();
					threadBE1.join();

					//Add BE results.
					ret.addAll(backendThread1.retBE);
					ret.addAll(backendThread0.retBE);
				}
				else if (numBE == 1) {
					//Start a job for one BE
					ThreadedCheckBE backendThread = new ThreadedCheckBE(password.subList(8, 16), hash.subList(8, 16), backendServerPool.get(0).element());
					Thread threadBE = new Thread(backendThread);
					threadBE.start();

					//Start a job for both FE threads
					ThreadedCheckFE frontendThread = new ThreadedCheckFE(password.subList(4, 8), hash.subList(4, 8));
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 4; ++i) {
						String onePwd = password.get(i);
						String oneHash = hash.get(i);
						ret.add(BCrypt.checkpw(onePwd, oneHash));
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);

					//Wait for BE to finish
					threadBE.join();

					//Add BE results.
					ret.addAll(backendThread.retBE);
				}
				else {
					//Start a job for both FE threads
					ThreadedCheckFE frontendThread = new ThreadedCheckFE(password.subList(8, 16), hash.subList(8, 16));
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 8; ++i) {
						String onePwd = password.get(i);
						String oneHash = hash.get(i);
						ret.add(BCrypt.checkpw(onePwd, oneHash));
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);
				}
			}
			//Multiple client (round robin + split)
			else if (numPass == 4) {
				int server = roundRobin.getAndIncrement() % (numBE + 1);
				if (server == 0) {
					//Start a job for both FE threads
					ThreadedCheckFE frontendThread = new ThreadedCheckFE(password.subList(2, 4), hash.subList(2, 4));
					Thread threadFE = new Thread(frontendThread);
					threadFE.start();
					for (int i = 0; i < 2; ++i) {
						String onePwd = password.get(i);
						String oneHash = hash.get(i);
						ret.add(BCrypt.checkpw(onePwd, oneHash));
					}
					threadFE.join();
					ret.addAll(frontendThread.retFE);
				}
				//Start a job for one BE
				else {
					//Block until BE socket is available
					BcryptServiceBE.Client backendThread = backendServerPool.get(server - 1).take();
					List<Boolean> check = backendThread.checkPassword(password, hash);
					backendServerPool.get(server - 1).add(backendThread);
					ret.addAll(check);
				}
			}
			//Multiple client (round robin)
			else {
				int server = roundRobin.getAndIncrement() % (numBE + 1);
				//Start a job for one FE thread
				if (server == 0) {
					String onePwd = password.get(0);
					String oneHash = hash.get(0);
					ret.add(BCrypt.checkpw(onePwd, oneHash));
				}
				//Start a job for one BE
				else {
					//Block until BE socket is available
					BcryptServiceBE.Client backendThread = backendServerPool.get(server - 1).take();
					List<Boolean> check = backendThread.checkPassword(password, hash);
					backendServerPool.get(server - 1).add(backendThread);
					ret.addAll(check);
				}
			}
			//Check for errors
			if (ret.size() != password.size()) throw new IllegalArgument();
			
			return ret;
		} catch (Exception e) {
			throw new IllegalArgument("Malformed hash");
		}
	}

	public void backendUp(String host, int port) throws IllegalArgument, org.apache.thrift.TException
	{
		while (true) {
			try {
				//8 threads seems like enough to avoid blocking (On 2 cores)
				//Context switching with 8 threads seems to be cheaper than blocking on 2 threads.
				int backendThreads = 8;
				BlockingQueue<BcryptServiceBE.Client> socketList = new LinkedBlockingQueue<>(backendThreads);
				for (int i = 0; i < backendThreads; ++i) {
					TSocket sock = new TSocket(host, port);
					TTransport transport = new TFramedTransport(sock);
					TProtocol protocol = new TBinaryProtocol(transport);
					BcryptServiceBE.Client client = new BcryptServiceBE.Client(protocol);
					transport.open();
					socketList.add(client);
				}
				//Sync just incase two BE add at same time
				synchronized (this) { backendServerPool.add(socketList); }
				break;
			} catch (Exception e) {
				//Just incase BE server is not setup yet.
				continue;
			}
		}
	}
}

class ThreadedHashFE extends Thread {
	List<String> password;
	List<String> retFE;
	short logRounds;
	ThreadedHashFE(List<String> password, short logRounds)
	{
		this.password = password;
		this.logRounds = logRounds;
		this.retFE = new ArrayList<>(password.size());
	}
	public void run() 
	{
		//FE compute
		try {
			for (int i = 0; i < password.size(); ++i) {
				String onePwd = password.get(i);
				String oneHash = BCrypt.hashpw(onePwd, BCrypt.gensalt(logRounds));
				retFE.add(oneHash);
			}
		} catch (Exception e) {}
	}
}

class ThreadedHashBE extends Thread {
	List<String> password;
	List<String> retBE;
	short logRounds;
	BcryptServiceBE.Client backendSocket;
	ThreadedHashBE(List<String> password, short logRounds, BcryptServiceBE.Client backendSocket)
	{
		this.password = password;
		this.logRounds = logRounds;
		this.backendSocket = backendSocket;
	}
	public void run() 
	{
		//BE compute
		try {
			retBE = backendSocket.hashPassword(password, logRounds);
		}
		catch (Exception e) {}
	}
}

class ThreadedCheckFE extends Thread
{
	List<String> password;
	List<String> hash;
	List<Boolean> retFE;
	ThreadedCheckFE(List<String> password, List<String> hash)
	{
		this.password = password;
		this.hash = hash;
		this.retFE = new ArrayList<>(password.size());
	}
	public void run() 
	{
		//FE compute
		try {
			for (int i = 0; i < password.size(); ++i) {
				String onePwd = password.get(i);
				String oneHash = hash.get(i);
				retFE.add(BCrypt.checkpw(onePwd, oneHash));
			}
		} catch (Exception e) {}
	}
}

class ThreadedCheckBE extends Thread
{
	List<String> password;
	List<String> hash;
	List<Boolean> retBE;
	BcryptServiceBE.Client backendSocket;
	ThreadedCheckBE(List<String> password, List<String> hash, BcryptServiceBE.Client backendSocket)
	{
		this.password = password;
		this.hash = hash;
		this.backendSocket = backendSocket;
	}
	public void run() 
	{
		//BE compute
		try {
			retBE = backendSocket.checkPassword(password, hash);
		} catch (Exception e) {}
	}
}
