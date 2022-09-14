<!-- C3 Specialization Track -->

## 1. Read through Secured Coding + Clean Code course in C3 learning path 

&nbsp;

## 2. Agile Practice read through (2 hour course)

&nbsp;

## 3. External training (Essential Practice for Agile team)

&nbsp;

## 4. Design Specifications

&nbsp;

## 5. Software Infrastructure (Kafka) - Know what Kafka does 
 - Messaging Platform
 - Topic (send message across, peer to peer or streaming?)
 - Container, trailer, Ops operator (topic) (information related to these entities)
 - queue (put message into the queue), the message contains the topic
 - publisher and subscriber (publisher will send topic into queue)
 - subscriber will extract the topic that he is interested in (peer to peer messaging having a topic)
 - within a topic will have sub-topics
 - message will have timestamp (make sure message sequence is right)
 - How to extract the timestamp and sequence it accordingly (Keypoint)
 - Event driven Architecture with microservice 

---
&nbsp;

## 6. Gitlab server (after 1 week of previous topics)
 - Assignment 1 & 2 as Group work 
 - Everyone stores code into GitLab
 - Team decide how to slice the Gitlab repositories (1 or 2 repositories?)
 - Tend to have 2 repositories so can have different release timings 
 - Residing in 1 person laptop
 - Can work from home as long as can deliver

&nbsp;

 ### Setup GitLab server use Hostname
  - windows directory (T6_git) hostname

&nbsp;

## 7. Branching strategy 
 - Discuss through
 - Must Know

&nbsp;

## 8. Trunk-based development
 - Main --> setup repository (without L1DS automation)
 - source code (src)
 - built script --> built.sh file (entrypoint)
                --> deploy.sh (one machine will be test server)
 - config folder (.env file) can be (test.env) or (production.env)

 - Decide if frontend or backend repository or put 2 together

 - After baseline folders mentioned above, create feature branch (dev branch) --> do all development here (team members will clone this branch to PC)
 - All developers will clone this repository (development branch) and do CP approach (commit all changes on laptop and pull changes from GitLab server)

 - When setup and ready, demonstrate to Chuan Wu 
 - Branch out from dev branch -> Rel_Assignment1.O

 - When ready, create another Rel_Assignment1.1.O 
 - Iteration number is equals to number of times Assignment 1 is evaluated 
 - When all done, deliver Assignment 1 back to main

 - After Assignment 1 done, clone Assignment 2 repository, similar to Assignment 1 
 - From official Assignment 1 code, create another branch (dev_emergencyfix)
 - When done with emergency fix, create another Rel_Assignment1.1EF1

---

 ## 1. Gitlab server setup 

 &nbsp;

 ## 2. Branching Strategy

&nbsp;

 ## 3. CICD pipeline
 - Automation
 - Contains a built
 - test frontend 

&nbsp;

## 4. How to trigger pipeline? 

&nbsp;

## 5. Coding Standard (Frontend & Backend)

&nbsp;

## write pipeline to test, do not need to containerize 

&nbsp;

## Development Component (GO & Svelt)

&nbsp;

## Persona and User Story and N-tier Architecture (Presentation)

