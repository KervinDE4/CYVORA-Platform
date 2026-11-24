
import { useEffect, useState } from "react";
import { supabase } from "./lib/supabase";

function App() {
  const [status, setStatus] = useState("Testing Supabase connection...");

  useEffect(() => {
    async function testConnection() {
      const { error } = await supabase
        .from("verified_contacts")
        .select("id")
        .limit(1);

      if (error) {
        setStatus(`Connection error: ${error.message}`);
      } else {
        setStatus("Connected to CYVORA Supabase successfully!");
      }
    }

    testConnection();
  }, []);

  return (
    <main style={{ padding: "40px", fontFamily: "Arial" }}>
      <h1>CYVORA</h1>
      <h2>CallTrust Module</h2>
      <p>{status}</p>
    </main>
  );
}

export default App;
