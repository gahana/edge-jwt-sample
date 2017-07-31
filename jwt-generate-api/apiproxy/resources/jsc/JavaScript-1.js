var claims = context.getVariable("jwt.claims");
var claimsJSON = JSON.stringify(claims);
context.setVariable("jwt.claimsJSON", claimsJSON);

print(claims);
print(claimsJSON);
print(context.getVariable("jwt.claimsJSON"));