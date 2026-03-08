import java.net.*;
import java.io.*;
import java.util.*;

/**
 * DS-FTP Sender Implementation
 * 
 * Implements both Stop-and-Wait and Go-Back-N protocol variants
 * Handles packet permutation via ChaosEngine for GBN mode
 * 
 * Command line: 
 *   Stop-and-Wait: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms>
 *   Go-Back-N:    java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> <window_size>
 */
public class Sender {
    
    // Socket for receiving ACKs
    private DatagramSocket ackSocket;
    
    // Receiver's address and port for data packets
    private InetAddress receiverAddress;
    private int receiverDataPort;
    
    // Sender's ACK listening port
    private int senderAckPort;
    
    // Input file
    private String inputFileName;
    private FileInputStream fileInputStream;
    
    // Protocol parameters
    private int timeoutMs;
    private Integer windowSize; // null for Stop-and-Wait, non-null for GBN
    
    // Protocol state
    private int base = 0;           // Oldest unacknowledged packet
    private int nextSeqNum = 0;      // Next sequence number to send
    private int expectedAck = 0;      // Expected ACK for Stop-and-Wait
    
    // Timeout management
    private long lastPacketSentTime;
    private boolean waitingForAck = false;
    private int consecutiveTimeouts = 0;
    private int lastBase = -1;
    private int consecutiveTimeoutsForSamePacket = 0;
    private static final int MAX_CONSECUTIVE_TIMEOUTS = 3;
    
    // Packet storage
    private List<DSPacket> allDataPackets = new ArrayList<>();  // All data packets
    private Map<Integer, DSPacket> windowPackets = new HashMap<>(); // Packets in current window
    
    // Statistics for performance measurement
    private int packetsSent = 0;
    private int packetsRetransmitted = 0;
    private int timeoutsOccurred = 0;
    
    // File information
    private long fileSize;
    private int totalPackets;
    private int lastDataSeqNum = 0;
    
    // Timing
    private long startTime;
    private long endTime;
    
    // Logging
    private PrintWriter logger;
    
    public Sender(String rcvIp, int rcvDataPort, int senderAckPort, 
                  String inputFile, int timeoutMs, Integer windowSize) throws Exception {
        
        this.receiverAddress = InetAddress.getByName(rcvIp);
        this.receiverDataPort = rcvDataPort;
        this.senderAckPort = senderAckPort;
        this.inputFileName = inputFile;
        this.timeoutMs = timeoutMs;
        this.windowSize = windowSize;
        
        // Create socket for receiving ACKs
        ackSocket = new DatagramSocket(senderAckPort);
        ackSocket.setReuseAddress(true);
        
        // Validate input file before opening
        validateInputFile();
        
        // Open input file
        File file = new File(inputFileName);
        fileSize = file.length();
        fileInputStream = new FileInputStream(file);
        
        // Calculate total packets (each DATA packet carries 124 bytes, except last)
        totalPackets = (int) Math.ceil((double) fileSize / DSPacket.MAX_PAYLOAD_SIZE);
        
        // Setup logging
        logger = new PrintWriter(new FileWriter("sender_log.txt"), true);
        log("Sender started");
        log("Sending to " + rcvIp + ":" + rcvDataPort);
        log("Listening for ACKs on port " + senderAckPort);
        log("Timeout: " + timeoutMs + "ms");
        log("Window size: " + (windowSize == null ? "Stop-and-Wait" : windowSize));
        log("File: " + inputFile + " (" + fileSize + " bytes, " + totalPackets + " packets)");
    }
    
    /**
     * Validate input file exists and is readable
     */
    private void validateInputFile() throws FileNotFoundException {
        File file = new File(inputFileName);
        if (!file.exists()) {
            throw new FileNotFoundException("Input file not found: " + inputFileName + 
                "\nPlease ensure the file exists in the current directory: " + 
                System.getProperty("user.dir"));
        }
        if (!file.canRead()) {
            throw new SecurityException("Cannot read input file: " + inputFileName);
        }
        if (file.length() == 0) {
            System.out.println("Warning: Input file is empty (0 bytes)");
        }
        log("Input file validated: " + inputFileName + " (" + file.length() + " bytes)");
    }
    
    /**
     * Main sender logic
     */
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        
        try {
            // Phase 1: Handshake - Send SOT
            if (!performHandshake()) {
                log("Handshake failed. Exiting.");
                return;
            }
            
            // Phase 2: Data Transfer
            if (fileSize == 0) {
                // Empty file case - send EOT immediately
                log("Empty file detected, sending EOT immediately");
                sendEOT();
                waitForEOTAck();
                return;
            }
            
            // Read all file data into packets
            readAllPackets();
            
            if (windowSize == null) {
                // Stop-and-Wait mode
                runStopAndWait();
            } else {
                // Go-Back-N mode
                runGoBackN();
            }
            
            // Phase 3: Wait for EOT ACK
            waitForEOTAck();
            
        } catch (Exception e) {
            log("Error during transfer: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }
    
    /**
     * Read all file data into packets with better error handling
     */
    private void readAllPackets() throws Exception {
        byte[] buffer = new byte[DSPacket.MAX_PAYLOAD_SIZE];
        int bytesRead;
        int seq = 1;
        int totalBytesRead = 0;
        
        log("Starting to read file: " + inputFileName);
        
        while ((bytesRead = fileInputStream.read(buffer)) != -1) {
            if (bytesRead > 0) {
                byte[] payload = Arrays.copyOf(buffer, bytesRead);
                DSPacket packet = new DSPacket(DSPacket.TYPE_DATA, seq, payload);
                allDataPackets.add(packet);
                totalBytesRead += bytesRead;
                
                if (seq % 10 == 0) { // Log every 10 packets
                    log("Read packet " + seq + " (" + bytesRead + " bytes, total: " + totalBytesRead + ")");
                }
                
                seq = (seq + 1) % 128;
            }
        }
        
        lastDataSeqNum = (seq - 1 + 128) % 128;
        log("File read complete: " + allDataPackets.size() + " packets, " + 
            totalBytesRead + " total bytes");
        
        if (allDataPackets.isEmpty()) {
            log("WARNING: File is empty!");
        }
    }
    
    /**
     * Perform handshake - Send SOT and wait for ACK
     */
    private boolean performHandshake() throws Exception {
        log("Starting handshake...");
        
        // Send SOT packet (Type 0, Seq 0)
        DSPacket sotPacket = new DSPacket(DSPacket.TYPE_SOT, 0, null);
        
        int attempts = 0;
        while (attempts < MAX_CONSECUTIVE_TIMEOUTS) {
            sendPacket(sotPacket, receiverAddress, receiverDataPort);
            log("Sent SOT, waiting for ACK...");
            
            try {
                ackSocket.setSoTimeout(timeoutMs);
                DSPacket ack = receiveAck();
                if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == 0) {
                    log("Handshake successful: Received ACK for SOT");
                    base = 0;
                    nextSeqNum = 1; // First DATA packet will be seq 1
                    expectedAck = 1; // For Stop-and-Wait
                    return true;
                }
            } catch (SocketTimeoutException e) {
                attempts++;
                log("Handshake timeout " + attempts + "/" + MAX_CONSECUTIVE_TIMEOUTS);
            }
        }
        
        log("Handshake failed after " + MAX_CONSECUTIVE_TIMEOUTS + " attempts");
        return false;
    }
    
    /**
     * Run Stop-and-Wait protocol
     */
    private void runStopAndWait() throws Exception {
        log("Starting Stop-and-Wait data transfer");
        
        int currentSeq = 1;
        int packetIndex = 0;
        
        while (packetIndex < allDataPackets.size()) {
            DSPacket dataPacket = allDataPackets.get(packetIndex);
            
            boolean ackReceived = false;
            consecutiveTimeouts = 0;
            consecutiveTimeoutsForSamePacket = 0;
            
            while (!ackReceived && consecutiveTimeouts < MAX_CONSECUTIVE_TIMEOUTS) {
                // Send packet
                sendPacket(dataPacket, receiverAddress, receiverDataPort);
                log("Stop-and-Wait: Sent DATA packet " + currentSeq);
                packetsSent++;
                
                // Wait for ACK
                try {
                    ackSocket.setSoTimeout(timeoutMs);
                    DSPacket ack = receiveAck();
                    if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == currentSeq) {
                        log("Stop-and-Wait: Received ACK for packet " + currentSeq);
                        ackReceived = true;
                        consecutiveTimeouts = 0;
                        consecutiveTimeoutsForSamePacket = 0;
                        currentSeq = (currentSeq + 1) % 128;
                        packetIndex++;
                    } else {
                        log("Stop-and-Wait: Received unexpected ACK " + ack.getSeqNum());
                    }
                } catch (SocketTimeoutException e) {
                    consecutiveTimeouts++;
                    consecutiveTimeoutsForSamePacket++;
                    timeoutsOccurred++;
                    log("Stop-and-Wait: Timeout " + consecutiveTimeouts + 
                        "/" + MAX_CONSECUTIVE_TIMEOUTS + " for packet " + currentSeq);
                    
                    if (consecutiveTimeoutsForSamePacket >= MAX_CONSECUTIVE_TIMEOUTS) {
                        log("CRITICAL FAILURE: " + MAX_CONSECUTIVE_TIMEOUTS + 
                            " consecutive timeouts for packet " + currentSeq + ". Terminating.");
                        throw new Exception("Critical failure - too many timeouts for same packet");
                    }
                }
            }
        }
        
        lastDataSeqNum = (currentSeq - 1 + 128) % 128;
        log("Stop-and-Wait data transfer complete. Last data seq: " + lastDataSeqNum);
    }
    
    /**
     * Run Go-Back-N protocol
     */
    private void runGoBackN() throws Exception {
        log("Starting Go-Back-N data transfer with window size " + windowSize);
        
        base = 1; // First DATA packet seq
        nextSeqNum = 1;
        lastPacketSentTime = System.currentTimeMillis();
        
        // Main GBN loop
        while (base <= totalPackets) {
            // Send packets within window
            while (nextSeqNum < base + windowSize && nextSeqNum <= totalPackets) {
                int packetIndex = nextSeqNum - 1;
                DSPacket packet = allDataPackets.get(packetIndex);
                
                // Check if this is the start of a group of 4 for permutation
                if (nextSeqNum % 4 == 1 && nextSeqNum + 3 <= totalPackets) {
                    // Send a permuted group of 4
                    sendPermutedGroup(packetIndex);
                    nextSeqNum += 4;
                } else if (nextSeqNum % 4 == 1 && packetIndex + 3 >= totalPackets) {
                    // Last group with fewer than 4 packets - send remaining in order
                    for (int i = packetIndex; i < totalPackets; i++) {
                        DSPacket p = allDataPackets.get(i);
                        sendPacket(p, receiverAddress, receiverDataPort);
                        log("GBN: Sent packet " + p.getSeqNum() + " (end of file)");
                        windowPackets.put(p.getSeqNum(), p);
                        packetsSent++;
                        nextSeqNum++;
                        lastPacketSentTime = System.currentTimeMillis();
                        Thread.sleep(5); // Small delay to help with ordering
                    }
                } else {
                    // Normal send
                    sendPacket(packet, receiverAddress, receiverDataPort);
                    log("GBN: Sent packet " + packet.getSeqNum());
                    windowPackets.put(packet.getSeqNum(), packet);
                    packetsSent++;
                    nextSeqNum++;
                    lastPacketSentTime = System.currentTimeMillis();
                    Thread.sleep(5); // Small delay to help with ordering
                }
                
                waitingForAck = true;
            }
            
            // Check for timeout
            if (waitingForAck && System.currentTimeMillis() - lastPacketSentTime > timeoutMs) {
                handleTimeout();
                continue;
            }
            
            // Try to receive ACK (non-blocking with short timeout)
            try {
                ackSocket.setSoTimeout(1); // Very short timeout to check for ACKs
                DSPacket ack = receiveAck();
                
                if (ack.getType() == DSPacket.TYPE_ACK) {
                    int ackNum = ack.getSeqNum();
                    log("GBN: Received cumulative ACK " + ackNum);
                    
                    if (ackNum >= base) {
                        // Update base
                        int oldBase = base;
                        base = ackNum + 1;
                        
                        // Check if we made progress
                        if (base > oldBase) {
                            consecutiveTimeoutsForSamePacket = 0;
                            lastBase = base;
                        }
                        
                        // Remove acknowledged packets from window
                        windowPackets.entrySet().removeIf(entry -> entry.getKey() <= ackNum);
                        
                        // Reset waiting flag if window is empty
                        waitingForAck = (base <= totalPackets);
                        if (waitingForAck) {
                            lastPacketSentTime = System.currentTimeMillis();
                        }
                    }
                }
            } catch (SocketTimeoutException e) {
                // No ACK received, continue loop to check timeout
            }
        }
        
        log("GBN data transfer complete");
    }
    
    /**
     * Send a permuted group of 4 packets
     */
    private void sendPermutedGroup(int startIndex) throws Exception {
        List<DSPacket> group = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            group.add(allDataPackets.get(startIndex + i));
        }
        
        // Apply ChaosEngine permutation
        List<DSPacket> permuted = ChaosEngine.permutePackets(group);
        
        // Send in permuted order
        for (DSPacket p : permuted) {
            sendPacket(p, receiverAddress, receiverDataPort);
            log("GBN: Sent packet " + p.getSeqNum() + " (permuted)");
            windowPackets.put(p.getSeqNum(), p);
            packetsSent++;
            Thread.sleep(5); // Small delay to help with ordering on network
        }
    }
    
    /**
     * Handle timeout in GBN mode
     */
    private void handleTimeout() throws Exception {
        timeoutsOccurred++;
        consecutiveTimeouts++;
        
        // Check for critical failure (3 consecutive timeouts for same base)
        if (base == lastBase) {
            consecutiveTimeoutsForSamePacket++;
            if (consecutiveTimeoutsForSamePacket >= MAX_CONSECUTIVE_TIMEOUTS) {
                log("CRITICAL FAILURE: " + MAX_CONSECUTIVE_TIMEOUTS + 
                    " consecutive timeouts for base=" + base + ". Terminating.");
                throw new Exception("Critical failure - too many timeouts for same packet");
            }
        } else {
            consecutiveTimeoutsForSamePacket = 1;
            lastBase = base;
        }
        
        log("GBN: Timeout " + consecutiveTimeouts + "/" + MAX_CONSECUTIVE_TIMEOUTS + 
            " - no ACK received for base=" + base);
        
        // Retransmit all packets in current window
        log("GBN: Retransmitting window from base " + base + " to " + 
            Math.min(base + windowSize - 1, totalPackets));
        
        for (int i = base; i < base + windowSize && i <= totalPackets; i++) {
            int packetIndex = i - 1;
            DSPacket packet = allDataPackets.get(packetIndex);
            sendPacket(packet, receiverAddress, receiverDataPort);
            log("GBN: Retransmitted packet " + packet.getSeqNum());
            packetsRetransmitted++;
            packetsSent++;
        }
        
        // Reset timer
        lastPacketSentTime = System.currentTimeMillis();
    }
    
    /**
     * Send EOT packet
     */
    private void sendEOT() throws Exception {
        int eotSeq;
        if (fileSize == 0) {
            eotSeq = 1; // Empty file case
        } else {
            eotSeq = (lastDataSeqNum + 1) % 128;
        }
        
        DSPacket eotPacket = new DSPacket(DSPacket.TYPE_EOT, eotSeq, null);
        sendPacket(eotPacket, receiverAddress, receiverDataPort);
        log("Sent EOT with seq " + eotSeq);
        packetsSent++;
    }
    
    /**
     * Wait for EOT acknowledgment
     */
    private void waitForEOTAck() throws Exception {
        int attempts = 0;
        
        while (attempts < MAX_CONSECUTIVE_TIMEOUTS) {
            try {
                ackSocket.setSoTimeout(timeoutMs);
                DSPacket ack = receiveAck();
                if (ack.getType() == DSPacket.TYPE_ACK) {
                    log("Received EOT ACK for seq " + ack.getSeqNum());
                    endTime = System.currentTimeMillis();
                    double totalTime = (endTime - startTime) / 1000.0;
                    System.out.printf("Total Transmission Time: %.2f seconds%n", totalTime);
                    return;
                }
            } catch (SocketTimeoutException e) {
                attempts++;
                log("EOT ACK timeout " + attempts + "/" + MAX_CONSECUTIVE_TIMEOUTS);
                if (attempts < MAX_CONSECUTIVE_TIMEOUTS) {
                    sendEOT(); // Resend EOT
                }
            }
        }
        
        log("Failed to receive EOT ACK after " + MAX_CONSECUTIVE_TIMEOUTS + " attempts");
    }
    
    /**
     * Send a packet to the receiver
     */
    private void sendPacket(DSPacket packet, InetAddress address, int port) throws Exception {
        byte[] data = packet.toBytes();
        DatagramPacket dp = new DatagramPacket(data, data.length, address, port);
        ackSocket.send(dp);
        
        log("Sent: Type=" + packet.getType() + ", Seq=" + packet.getSeqNum() + 
            ", Len=" + packet.getLength());
    }
    
    /**
     * Receive an ACK packet
     */
    private DSPacket receiveAck() throws Exception {
        byte[] buffer = new byte[DSPacket.MAX_PACKET_SIZE];
        DatagramPacket dp = new DatagramPacket(buffer, buffer.length);
        ackSocket.receive(dp);
        
        DSPacket packet = new DSPacket(dp.getData());
        if (packet.getType() == DSPacket.TYPE_ACK) {
            log("Received ACK for seq " + packet.getSeqNum());
        }
        
        return packet;
    }
    
    /**
     * Clean up resources
     */
    private void cleanup() throws Exception {
        if (fileInputStream != null) {
            fileInputStream.close();
        }
        
        if (ackSocket != null && !ackSocket.isClosed()) {
            ackSocket.close();
        }
        
        if (logger != null) {
            // Print statistics
            log("\n=== Transfer Statistics ===");
            log("Total packets sent: " + packetsSent);
            log("Packets retransmitted: " + packetsRetransmitted);
            log("Timeouts occurred: " + timeoutsOccurred);
            log("Retransmission ratio: " + 
                (packetsSent > 0 ? (double)packetsRetransmitted/packetsSent : 0));
            
            logger.close();
        }
        
        log("Sender finished.");
    }
    
    /**
     * Logging utility
     */
    private void log(String message) {
        String timestamp = new java.text.SimpleDateFormat("HH:mm:ss.SSS").format(new Date());
        String logMessage = "[" + timestamp + "] " + message;
        System.out.println(logMessage);
        if (logger != null) {
            logger.println(logMessage);
        }
    }
    
    public static void main(String[] args) {
        // Validate command line arguments
        if (args.length < 5 || args.length > 6) {
            System.err.println("Usage: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> " +
                             "<input_file> <timeout_ms> [window_size]");
            System.err.println("Example (Stop-and-Wait): java Sender 127.0.0.1 4000 3000 small.txt 1000");
            System.err.println("Example (Go-Back-N):    java Sender 127.0.0.1 4000 3000 large.txt 1000 20");
            System.exit(1);
        }
        
        try {
            // Parse arguments
            String rcvIp = args[0];
            int rcvDataPort = Integer.parseInt(args[1]);
            int senderAckPort = Integer.parseInt(args[2]);
            String inputFile = args[3];
            int timeoutMs = Integer.parseInt(args[4]);
            Integer windowSize = null;
            
            if (args.length == 6) {
                windowSize = Integer.parseInt(args[5]);
                // Validate window size
                if (windowSize <= 0 || windowSize > 128) {
                    System.err.println("Window size must be between 1 and 128");
                    System.exit(1);
                }
                if (windowSize % 4 != 0) {
                    System.err.println("Window size must be a multiple of 4 for GBN");
                    System.exit(1);
                }
            }
            
            // Validate timeout
            if (timeoutMs <= 0) {
                System.err.println("Timeout must be positive");
                System.exit(1);
            }
            
            // Create and run sender
            Sender sender = new Sender(rcvIp, rcvDataPort, senderAckPort, 
                                      inputFile, timeoutMs, windowSize);
            sender.run();
            
        } catch (NumberFormatException e) {
            System.err.println("Invalid number format: " + e.getMessage());
            System.exit(1);
        } catch (FileNotFoundException e) {
            System.err.println("Input file not found: " + e.getMessage());
            System.err.println("Current directory: " + System.getProperty("user.dir"));
            System.exit(1);
        } catch (SocketException e) {
            System.err.println("Socket error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
