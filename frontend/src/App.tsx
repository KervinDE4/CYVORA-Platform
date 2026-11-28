import { useEffect, useMemo, useState } from "react";
import { supabase } from "./lib/supabase";
import Academy from "./Academy";

type VerifiedContact = {
  id: string;
  organization_name: string;
  category: string | null;
  official_phone: string | null;
  official_website: string | null;
  notes: string | null;
};

function App() {
  const [activeModule, setActiveModule] = useState<"call-trust" | "academy">("call-trust");
  const [contacts, setContacts] = useState<VerifiedContact[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchContacts();
  }, []);

  async function fetchContacts() {
    setLoading(true);
    setError("");

    const { data, error } = await supabase
      .from("verified_contacts")
      .select("*")
      .order("organization_name", { ascending: true });

    if (error) {
      console.error("CallTrust database error:", error);
      setError(error.message);
      setContacts([]);
    } else {
      setContacts((data || []) as VerifiedContact[]);
    }

    setLoading(false);
  }

  const filteredContacts = useMemo(() => {
    const term = search.toLowerCase().trim();
    if (!term) return contacts;

    return contacts.filter((contact) =>
      [
        contact.organization_name,
        contact.category,
        contact.official_phone,
        contact.official_website,
        contact.notes,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(term)
    );
  }, [contacts, search]);

  if (activeModule === "academy") {
    return (
      <>
        <button
          onClick={() => setActiveModule("call-trust")}
          style={{
            position: "fixed",
            zIndex: 120,
            top: "17px",
            left: "18px",
            border: "1px solid #dfe4f5",
            borderRadius: "9px",
            padding: "9px 13px",
            background: "#ffffffed",
            color: "#263b87",
            fontWeight: 800,
            fontSize: "11px",
            cursor: "pointer",
            boxShadow: "0 5px 18px #17233d18",
          }}
        >
          ← CYVORA modules
        </button>
        <Academy />
      </>
    );
  }

  return (
    <main style={{
      minHeight: "100vh",
      background: "#f4f6f8",
      color: "#1a1d20",
      fontFamily: "Arial, sans-serif"
    }}>
      <header style={{
        background: "#172d4b",
        color: "white",
        padding: "28px 7%"
      }}>
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px"
        }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "30px" }}>CYVORA</h1>
            <p style={{ marginBottom: 0, color: "#cbd5e1" }}>
              Digital Protection Platform
            </p>
          </div>
          <button
            onClick={() => setActiveModule("academy")}
            style={{
              border: "1px solid #91a9ca",
              background: "#ffffff",
              color: "#172d4b",
              borderRadius: "8px",
              padding: "12px 17px",
              fontWeight: 700,
              cursor: "pointer"
            }}
          >
            ✦ Open CYVORA Academy
          </button>
        </div>
      </header>

      <section style={{ maxWidth: "1050px", margin: "40px auto", padding: "0 20px" }}>
        <div style={{
          background: "white",
          padding: "28px",
          borderRadius: "12px",
          boxShadow: "0 3px 15px rgba(0,0,0,0.05)"
        }}>
          <p style={{
            color: "#2563eb",
            fontWeight: "bold",
            letterSpacing: "1px"
          }}>
            PROTECTION MODULE
          </p>

          <h2 style={{ fontSize: "27px", marginBottom: "8px" }}>
            CallTrust
          </h2>

          <p style={{ color: "#64748b" }}>
            Verify official contact details before trusting a caller
            or making a payment.
          </p>

          <hr style={{ border: "0", borderTop: "1px solid #e5e7eb", margin: "25px 0" }} />

          <h3>Verified Contacts</h3>

          <p style={{ color: "#64748b" }}>
            Search the official organisation directory.
          </p>

          <input
            type="text"
            placeholder="Search organisation, category or phone number..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "14px",
              border: "1px solid #cbd5e1",
              borderRadius: "7px",
              fontSize: "15px",
              margin: "12px 0 22px"
            }}
          />

          <div style={{
            display: "flex",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "12px",
            marginBottom: "18px"
          }}>
            <strong>Directory results</strong>
            <span style={{ color: "#64748b" }}>
              Showing {filteredContacts.length} of {contacts.length} records
            </span>
          </div>

          {loading && <p>Loading verified organisations...</p>}

          {error && (
            <div style={{
              padding: "15px",
              background: "#fee2e2",
              color: "#991b1b",
              borderRadius: "7px"
            }}>
              Database error: {error}
              <button onClick={fetchContacts} style={{ marginLeft: "12px" }}>
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filteredContacts.length === 0 && (
            <p style={{
              padding: "25px",
              background: "#f8fafc",
              borderRadius: "7px",
              color: "#64748b",
              textAlign: "center"
            }}>
              {contacts.length === 0
                ? "No verified organisations found in the database."
                : "No matching organisations found."}
            </p>
          )}

          <div style={{ display: "grid", gap: "15px" }}>
            {filteredContacts.map((contact) => (
              <article
                key={contact.id}
                style={{
                  border: "1px solid #e2e8f0",
                  padding: "20px",
                  borderRadius: "9px",
                  background: "#ffffff"
                }}
              >
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: "10px"
                }}>
                  <h3 style={{ margin: 0 }}>
                    {contact.organization_name}
                  </h3>

                  <span style={{
                    background: "#dcfce7",
                    color: "#166534",
                    padding: "5px 10px",
                    borderRadius: "20px",
                    fontSize: "12px",
                    fontWeight: "bold"
                  }}>
                    DIRECTORY LISTING
                  </span>
                </div>

                <p style={{ color: "#64748b" }}>
                  {contact.category || "Organisation"}
                </p>

                {contact.official_phone && (
                  <p>
                    <strong>Official phone:</strong>{" "}
                    {contact.official_phone}
                  </p>
                )}

                {contact.official_website && (
                  <p>
                    <strong>Website:</strong>{" "}
                    <a
                      href={contact.official_website}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {contact.official_website}
                    </a>
                  </p>
                )}

                {contact.notes && (
                  <p style={{ color: "#64748b" }}>
                    {contact.notes}
                  </p>
                )}
              </article>
            ))}
          </div>
        </div>
      </section>

      <footer style={{
        textAlign: "center",
        padding: "25px",
        color: "#64748b",
        fontSize: "13px"
      }}>
        CYVORA © 2026 | Protect. Verify. Report.
      </footer>
    </main>
  );
}

export default App;
