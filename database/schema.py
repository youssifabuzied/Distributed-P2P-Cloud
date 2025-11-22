class Schema:
    @staticmethod
    def Client():
        return """
       CREATE TABLE IF NOT EXISTS Client (
           user_name TEXT PRIMARY KEY,
           ip_addr TEXT NOT NULL,
           status INTEGER NOT NULL,
           time_stamp DATE NOT NULL
       );
       """

    @staticmethod
    def Image():
        return """
       CREATE TABLE IF NOT EXISTS Image (
           image_name TEXT PRIMARY KEY NOT NULL,
           image_bytes BLOB NOT NULL,
           user_name TEXT NOT NULL,
           FOREIGN KEY(user_name) REFERENCES Client(user_name)
       );
       """
