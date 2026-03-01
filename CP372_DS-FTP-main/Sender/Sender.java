import java.io.*;
import java.net.*;
import java.util.*;

/**
 * DS-FTP Sender (Mars Rover)
 * 
 * CP372 Assignment 2 - Deep Space File Transfer Protocol
 * 
 * Implements both Stop-and-Wait and Go-Back-N protocols
 * 
 * Command line: 
 *   Sender <rcv_ip> <rcv_data_port> <sender_ack_port> <input_file> <timeout_ms> [window_size]
 * 
 * Examples:
 *   Stop-and-Wait: java Sender localhost 8888 9876 input.txt 1000
 *   Go-Back-N:     java Sender localhost 8888 9876 input.txt 1000 20
 */
public class Sender {
    
    // Protocol constants
    private static final int MAX_PAYLOAD = 124;
    private static final int MAX_SEQ = 128;
    private static final int MAX_TIMEOUTS = 3;
    private static final int MAX_RETRANSMISSIONS = 5;
    
    // Connection parameters
    private InetAddress receiverIp;
    private int receiverDataPort;
    private int senderAckPort;
    private String inputFile;
    private int timeoutMs;
    private Integer windowSize; // null means Stop-and-Wait
    
    // Protocol state
    private DatagramSocket socket;
    private int base = 0;          // Oldest unACKed packet (1-indexed for DATA)
    private int nextSeq = 0;        // Next sequence number to send
    
    // Statistics and tracking
    private long startTime;
    private long endTime;
    private int consecutiveTimeouts = 0;
    private int totalTimeouts = 0;
    private int lastProgressSeq = -1;      // Last sequence that made progress
    private long lastProgressTime = 0;      // When last progress was made
    private int expectedAck = -1;           // For Stop-and-Wait: the ACK we're waiting for
    
    // File data
    private List<byte[]> fileChunks = new ArrayList<>();
    private int totalPackets;
    
    // For tracking sent packets in current window (GBN)
    private Map<Integer, DSPacket> sentPackets = new HashMap<>();
    private Map<Integer, Integer> packetRetransmissionCount = new HashMap<>();
    
    // Performance tracking
    private int totalPacketsSent = 0;
    private int totalRetransmissions = 0;
    private int duplicateAcks = 0;
    
    public static void main(String[] args) {
        if (args.length < 5 || args.length > 6) {
            System.err.println("Usage: java Sender <rcv_ip> <rcv_data_port> <sender_ack_port> " +
                              "<input_file> <timeout_ms> [window_size]");
            System.err.println("  window_size omitted → Stop-and-Wait");
            System.err.println("  window_size provided → Go-Back-N (must be multiple of 4, ≤128)");
            System.exit(1);
        }
        
        Sender sender = new Sender();
        sender.parseArgs(args);
        
        try {
            sender.run();
        } catch (Exception e) {
            System.err.println("Sender error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private void parseArgs(String[] args) {
        try {
            receiverIp = InetAddress.getByName(args[0]);
            receiverDataPort = Integer.parseInt(args[1]);
            senderAckPort = Integer.parseInt(args[2]);
            inputFile = args[3];
            timeoutMs = Integer.parseInt(args[4]);
            
            if (args.length == 6) {
                windowSize = Integer.parseInt(args[5]);
                if (windowSize % 4 != 0) {
                    throw new IllegalArgumentException("Window size must be a multiple of 4");
                }
                if (windowSize > MAX_SEQ) {
                    throw new IllegalArgumentException("Window size must be ≤ 128");
                }
                System.out.println("Running in Go-Back-N mode with window size = " + windowSize);
            } else {
                System.out.println("Running in Stop-and-Wait mode");
            }
        } catch (Exception e) {
            System.err.println("Invalid arguments: " + e.getMessage());
            System.exit(1);
        }
    }
    
    private void run() throws Exception {
        // Read and chunk the file
        readFile();
        
        // Create socket and set timeout
        socket = new DatagramSocket(senderAckPort);
        socket.setSoTimeout(timeoutMs);
        
        System.out.println("\n=== DS-FTP Sender Starting ===");
        System.out.println("Receiver IP: " + receiverIp);
        System.out.println("Receiver Data Port: " + receiverDataPort);
        System.out.println("Sender ACK Port: " + senderAckPort);
        System.out.println("Input File: " + inputFile);
        System.out.println("Timeout: " + timeoutMs + "ms");
        System.out.println("Total Packets: " + totalPackets + " (each up to " + MAX_PAYLOAD + " bytes)");
        System.out.println("==============================\n");
        
        // Start timing
        startTime = System.currentTimeMillis();
        lastProgressTime = startTime;
        
        // Perform handshake
        if (!performHandshake()) {
            System.err.println("Handshake failed - unable to establish connection");
            return;
        }
        
        // Handle empty file case
        if (totalPackets == 0) {
            System.out.println("Empty file detected, sending EOT immediately");
            sendEot(1);
            if (waitForEotAck()) {
                endTime = System.currentTimeMillis();
                printTransmissionTime();
            }
            socket.close();
            return;
        }
        
        // Transfer data based on protocol
        if (windowSize == null) {
            stopAndWaitTransfer();
        } else {
            goBackNTransfer();
        }
        
        // Teardown
        int eotSeq = (totalPackets % MAX_SEQ) + 1;
        sendEot(eotSeq);
        if (waitForEotAck()) {
            endTime = System.currentTimeMillis();
            printTransmissionTime();
        }
        
        // Print final statistics
        printStatistics();
        
        socket.close();
    }
    
    private void readFile() throws IOException {
        File file = new File(inputFile);
        if (!file.exists()) {
            System.err.println("Input file not found: " + inputFile);
            System.exit(1);
        }
        
        byte[] fileData = new byte[(int) file.length()];
        
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(fileData);
        }
        
        // Chunk the file into MAX_PAYLOAD byte pieces
        for (int i = 0; i < fileData.length; i += MAX_PAYLOAD) {
            int chunkSize = Math.min(MAX_PAYLOAD, fileData.length - i);
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(fileData, i, chunk, 0, chunkSize);
            fileChunks.add(chunk);
        }
        
        totalPackets = fileChunks.size();
        System.out.println("File loaded: " + file.length() + " bytes, " + totalPackets + " packets");
    }
    
    private boolean performHandshake() throws Exception {
        System.out.println("[HANDSHAKE] Initiating connection...");
        
        // Send SOT packet (Seq 0)
        DSPacket sotPacket = new DSPacket(DSPacket.TYPE_SOT, 0, null);
        sendPacket(sotPacket);
        System.out.println("[HANDSHAKE] Sent SOT (Seq 0)");
        totalPacketsSent++;
        
        // Wait for ACK with retries
        int handshakeRetries = 0;
        long handshakeStart = System.currentTimeMillis();
        
        while (handshakeRetries < MAX_TIMEOUTS && 
               System.currentTimeMillis() - handshakeStart < timeoutMs * 3) {
            try {
                DatagramPacket recvPacket = new DatagramPacket(
                    new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
                socket.receive(recvPacket);
                
                DSPacket ack = new DSPacket(recvPacket.getData());
                if (ack.getType() == DSPacket.TYPE_ACK && ack.getSeqNum() == 0) {
                    System.out.println("[HANDSHAKE] Received ACK for SOT - connection established");
                    lastProgressSeq = 0;
                    lastProgressTime = System.currentTimeMillis();
                    expectedAck = 0;
                    return true;
                }
            } catch (SocketTimeoutException e) {
                handshakeRetries++;
                totalTimeouts++;
                System.out.println("[HANDSHAKE] Timeout " + handshakeRetries + 
                                  "/" + MAX_TIMEOUTS + ", resending SOT");
                sendPacket(sotPacket);
                totalPacketsSent++;
            }
        }
        
        return false;
    }
    
    private void stopAndWaitTransfer() throws Exception {
        System.out.println("\n--- Stop-and-Wait Transfer Started ---");
        
        for (int i = 0; i < totalPackets; i++) {
            int seqNum = (i % MAX_SEQ) + 1; // DATA starts at seq 1
            boolean acked = false;
            int packetTimeouts = 0;
            int retransmissionCount = 0;
            
            // Set expected ACK for this packet
            expectedAck = seqNum;
            
            System.out.println("\n[Packet " + (i+1) + "/" + totalPackets + "] Sending DATA (Seq " + seqNum + ")");
            
            while (!acked) {
                // Send packet
                DSPacket dataPacket = new DSPacket(DSPacket.TYPE_DATA, seqNum, fileChunks.get(i));
                sendPacket(dataPacket);
                totalPacketsSent++;
                
                // Store for potential retransmission tracking
                sentPackets.put(seqNum, dataPacket);
                
                // Wait for ACK
                try {
                    while (true) {
                        DatagramPacket recvPacket = new DatagramPacket(
                            new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
                        socket.receive(recvPacket);
                        
                        DSPacket ack = new DSPacket(recvPacket.getData());
                        if (ack.getType() == DSPacket.TYPE_ACK) {
                            int ackSeq = ack.getSeqNum();
                            System.out.println("  Received ACK (Seq " + ackSeq + ")");
                            
                            // Check if this is the ACK we're waiting for
                            if (ackSeq == expectedAck) {
                                acked = true;
                                packetTimeouts = 0;
                                consecutiveTimeouts = 0;
                                lastProgressSeq = seqNum;
                                lastProgressTime = System.currentTimeMillis();
                                System.out.println("  ✓ Packet " + seqNum + " acknowledged");
                                break;
                            } else {
                                // Duplicate or unexpected ACK
                                duplicateAcks++;
                                System.out.println("  ⚠ Unexpected ACK " + ackSeq + 
                                                  " (waiting for " + expectedAck + ")");
                            }
                        }
                    }
                } catch (SocketTimeoutException e) {
                    packetTimeouts++;
                    consecutiveTimeouts++;
                    totalTimeouts++;
                    retransmissionCount++;
                    System.out.println("  ✗ Timeout " + packetTimeouts + 
                                      "/" + MAX_TIMEOUTS + " for packet " + seqNum);
                    
                    // Track retransmissions
                    packetRetransmissionCount.put(seqNum, retransmissionCount);
                    totalRetransmissions++;
                    
                    // Check for critical failure
                    if (packetTimeouts >= MAX_TIMEOUTS) {
                        System.err.println("\n!!! CRITICAL FAILURE: " + MAX_TIMEOUTS + 
                                         " consecutive timeouts for packet " + seqNum + 
                                         " - Unable to transfer file.");
                        System.err.println("Last progress made on packet: " + lastProgressSeq);
                        System.err.println("Time since last progress: " + 
                                         (System.currentTimeMillis() - lastProgressTime) + "ms");
                        System.exit(1);
                    }
                }
            }
        }
        
        System.out.println("\n--- Stop-and-Wait Transfer Complete ---");
    }
    
    private void goBackNTransfer() throws Exception {
        System.out.println("\n--- Go-Back-N Transfer Started (Window Size = " + windowSize + ") ---");
        
        base = 1; // First DATA packet seq = 1
        nextSeq = 1;
        
        while (base <= totalPackets) {
            System.out.println("\n[Window] base=" + base + ", nextSeq=" + nextSeq + 
                              ", window=[" + base + "-" + Math.min(base + windowSize - 1, totalPackets) + "]");
            
            // Send all packets in current window
            while (nextSeq < base + windowSize && nextSeq <= totalPackets) {
                int seqNum = ((nextSeq - 1) % MAX_SEQ) + 1;
                DSPacket dataPacket = new DSPacket(DSPacket.TYPE_DATA, seqNum, 
                                                   fileChunks.get(nextSeq - 1));
                
                // Store for potential retransmission
                sentPackets.put(nextSeq, dataPacket);
                
                // Initialize retransmission count if not exists
                if (!packetRetransmissionCount.containsKey(nextSeq)) {
                    packetRetransmissionCount.put(nextSeq, 0);
                }
                
                // Prepare window group for permutation
                List<DSPacket> windowGroup = new ArrayList<>();
                windowGroup.add(dataPacket);
                
                // Add next up to 3 packets if available
                for (int i = 1; i < 4 && nextSeq + i <= totalPackets; i++) {
                    int nextSeqNum = ((nextSeq + i - 1) % MAX_SEQ) + 1;
                    DSPacket nextPacket = new DSPacket(DSPacket.TYPE_DATA, nextSeqNum, 
                                        fileChunks.get(nextSeq + i - 1));
                    windowGroup.add(nextPacket);
                    sentPackets.put(nextSeq + i, nextPacket);
                }
                
                // Apply chaos permutation
                List<DSPacket> permuted = ChaosEngine.permutePackets(windowGroup);
                
                // Send permuted packets
                System.out.print("  Sending group: ");
                for (DSPacket pkt : permuted) {
                    sendPacket(pkt);
                    totalPacketsSent++;
                    System.out.print(pkt.getSeqNum() + " ");
                }
                System.out.println();
                
                nextSeq += windowGroup.size();
                Thread.sleep(10); // Small delay to avoid flooding
            }
            
            // Wait for ACKs
            try {
                DatagramPacket recvPacket = new DatagramPacket(
                    new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
                socket.receive(recvPacket);
                
                DSPacket ack = new DSPacket(recvPacket.getData());
                if (ack.getType() == DSPacket.TYPE_ACK) {
                    int ackSeq = ack.getSeqNum();
                    System.out.println("  Received cumulative ACK (Seq " + ackSeq + ")");
                    
                    // Convert ACK seq to packet index (1-based)
                    int ackIndex;
                    if (ackSeq == 0) {
                        ackIndex = totalPackets; // Wrapped around
                    } else {
                        ackIndex = ackSeq;
                    }
                    
                    // For cumulative ACK, advance base to ackIndex + 1
                    if (ackIndex >= base) {
                        int oldBase = base;
                        base = ackIndex + 1;
                        consecutiveTimeouts = 0;
                        lastProgressSeq = ackIndex;
                        lastProgressTime = System.currentTimeMillis();
                        expectedAck = ackIndex; // Update expected ACK for tracking
                        System.out.println("  Window advanced: " + oldBase + " → " + base);
                        
                        // Clean up sent packets cache
                        for (int i = oldBase; i < base; i++) {
                            sentPackets.remove(i);
                        }
                    } else {
                        // Duplicate ACK
                        duplicateAcks++;
                        System.out.println("  ⚠ Duplicate ACK " + ackSeq + " (base=" + base + ")");
                    }
                }
            } catch (SocketTimeoutException e) {
                consecutiveTimeouts++;
                totalTimeouts++;
                System.out.println("  ✗ Timeout " + consecutiveTimeouts + 
                                  "/" + MAX_TIMEOUTS + " - Retransmitting window from base=" + base);
                
                // Check for critical failure using lastProgressSeq
                if (consecutiveTimeouts >= MAX_TIMEOUTS) {
                    System.err.println("\n!!! CRITICAL FAILURE: " + MAX_TIMEOUTS + 
                                     " consecutive timeouts - Unable to transfer file.");
                    System.err.println("Last progress made on packet: " + lastProgressSeq);
                    System.err.println("Time since last progress: " + 
                                     (System.currentTimeMillis() - lastProgressTime) + "ms");
                    System.exit(1);
                }
                
                // Increment retransmission counts for packets in window
                for (int i = base; i < nextSeq && i <= totalPackets; i++) {
                    int currentRetries = packetRetransmissionCount.getOrDefault(i, 0) + 1;
                    packetRetransmissionCount.put(i, currentRetries);
                    totalRetransmissions++;
                    
                    // Check individual packet retransmission limit
                    if (currentRetries >= MAX_RETRANSMISSIONS) {
                        System.err.println("\n!!! CRITICAL FAILURE: Packet " + i + 
                                         " retransmitted " + currentRetries + 
                                         " times - Unable to transfer file.");
                        System.exit(1);
                    }
                }
                
                // Retransmit entire window from base
                nextSeq = base;
                
                // Small delay before retransmission
                Thread.sleep(10);
            }
        }
        
        System.out.println("\n--- Go-Back-N Transfer Complete ---");
    }
    
    private void sendEot(int seqNum) throws Exception {
        DSPacket eotPacket = new DSPacket(DSPacket.TYPE_EOT, seqNum, null);
        sendPacket(eotPacket);
        totalPacketsSent++;
        System.out.println("[TEARDOWN] Sent EOT (Seq " + seqNum + ")");
    }
    
    private boolean waitForEotAck() throws Exception {
        long eotStart = System.currentTimeMillis();
        int eotRetries = 0;
        
        while (eotRetries < MAX_TIMEOUTS && 
               System.currentTimeMillis() - eotStart < timeoutMs * 3) {
            try {
                DatagramPacket recvPacket = new DatagramPacket(
                    new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
                socket.receive(recvPacket);
                
                DSPacket ack = new DSPacket(recvPacket.getData());
                if (ack.getType() == DSPacket.TYPE_ACK) {
                    System.out.println("[TEARDOWN] Received EOT ACK (Seq " + ack.getSeqNum() + ")");
                    lastProgressSeq = ack.getSeqNum();
                    lastProgressTime = System.currentTimeMillis();
                    return true;
                }
            } catch (SocketTimeoutException e) {
                eotRetries++;
                totalTimeouts++;
                System.out.println("[TEARDOWN] Timeout " + eotRetries + 
                                  "/" + MAX_TIMEOUTS + ", resending EOT");
                int seqNum = (totalPackets % MAX_SEQ) + 1;
                sendEot(seqNum);
            }
        }
        
        System.err.println("[TEARDOWN] Failed to receive EOT ACK");
        return false;
    }
    
    private void sendPacket(DSPacket packet) throws Exception {
        byte[] data = packet.toBytes();
        DatagramPacket datagram = new DatagramPacket(data, data.length, 
                                                     receiverIp, receiverDataPort);
        socket.send(datagram);
    }
    
    private void printTransmissionTime() {
        double seconds = (endTime - startTime) / 1000.0;
        System.out.printf("\n=== Transmission Complete ===\n");
        System.out.printf("Total Transmission Time: %.2f seconds\n", seconds);
    }
    
    private void printStatistics() {
        System.out.println("\n=== Sender Statistics ===");
        System.out.println("Total packets sent: " + totalPacketsSent);
        System.out.println("Total retransmissions: " + totalRetransmissions);
        System.out.println("Total timeouts: " + totalTimeouts);
        System.out.println("Duplicate ACKs received: " + duplicateAcks);
        System.out.println("Last progress sequence: " + lastProgressSeq);
        
        if (!packetRetransmissionCount.isEmpty()) {
            int maxRetries = packetRetransmissionCount.values().stream()
                                .mapToInt(Integer::intValue)
                                .max()
                                .orElse(0);
            System.out.println("Maximum retransmissions for a single packet: " + maxRetries);
        }
        
        System.out.println("===========================");
    }
}