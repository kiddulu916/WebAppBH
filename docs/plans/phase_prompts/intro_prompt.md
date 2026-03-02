# PROJECT INITIATION: WebAppBH FRAMEWORK

I am building a 12-phase modular, event-driven Bug Bounty Framework called "WebAppBH"

## **System Architecture:**

  1. A centralized PostgreSQL DB (OAM-compliant).
  2. A Redis Message Broker for event-driven tasking.
  3. A FastAPI Orchestrator managing a fleet of specialized Docker workers.
  4. A shared volume (/app/shared/) for configs, raw outputs, and logs.
  5. A Next.js Dashboard for Command & Control.

## **Your Role:**

I will provide a detailed prompt for each phase sequentially. You must ensure that every piece of code you generate uses the shared models, respects the database schema, and adheres to the established inter-container communication protocols. 

## **Instruction:**

Do not hallucinate table names or directory paths. Refer back to the 'Shared Library' we create in Phase 1 for all DB interactions. Acknowledge this plan, and wait for Phase 1.
