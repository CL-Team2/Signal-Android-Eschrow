package org.thoughtcrime.securesms.jobs;

import android.content.Context;
import android.util.Log;

import org.thoughtcrime.securesms.ApplicationContext;
import org.thoughtcrime.securesms.crypto.MasterSecret;
import org.thoughtcrime.securesms.crypto.storage.TextSecureSessionStore;
import org.thoughtcrime.securesms.database.DatabaseFactory;
import org.thoughtcrime.securesms.database.EncryptingSmsDatabase;
import org.thoughtcrime.securesms.database.NoSuchMessageException;
import org.thoughtcrime.securesms.database.SmsDatabase;
import org.thoughtcrime.securesms.database.model.SmsMessageRecord;
import org.thoughtcrime.securesms.dependencies.InjectableType;
import org.thoughtcrime.securesms.notifications.MessageNotifier;
import org.thoughtcrime.securesms.recipients.RecipientFactory;
import org.thoughtcrime.securesms.recipients.Recipients;
import org.thoughtcrime.securesms.service.ExpiringMessageManager;
import org.thoughtcrime.securesms.transport.InsecureFallbackApprovalException;
import org.thoughtcrime.securesms.transport.RetryLaterException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.api.util.InvalidNumberException;

import java.io.IOException;

import javax.inject.Inject;

import static org.thoughtcrime.securesms.dependencies.SignalCommunicationModule.SignalMessageSenderFactory;

public class PushTextSendJob extends PushSendJob implements InjectableType {

  private static final long serialVersionUID = 1L;

  private static final String TAG = PushTextSendJob.class.getSimpleName();

  @Inject transient SignalMessageSenderFactory messageSenderFactory;

  private final long messageId;

  public PushTextSendJob(Context context, long messageId, String destination) {
    super(context, constructParameters(context, destination));
    this.messageId = messageId;

    TextSecureSessionStore store = new TextSecureSessionStore(context);
    SessionRecord record = store.loadSession(new SignalProtocolAddress(destination, SignalServiceAddress.DEFAULT_DEVICE_ID));
    MessageKeys predicted = record.getSessionState().getSenderChainKey().getMessageKeys();
    int i = 0+1;

//    SessionRecord record = new SessionRecord();
  }

  @Override
  public void onAdded() {}

  @Override
  public void onPushSend(MasterSecret masterSecret) throws NoSuchMessageException, RetryLaterException {
    ExpiringMessageManager expirationManager = ApplicationContext.getInstance(context).getExpiringMessageManager();
    EncryptingSmsDatabase  database          = DatabaseFactory.getEncryptingSmsDatabase(context);
    SmsMessageRecord       record            = database.getMessage(masterSecret, messageId);

    try {
      Log.w(TAG, "Sending message: " + messageId);

      deliver(record);
      database.markAsSent(messageId, true);

      if (record.getExpiresIn() > 0) {
        database.markExpireStarted(messageId);
        expirationManager.scheduleDeletion(record.getId(), record.isMms(), record.getExpiresIn());
      }

    } catch (InsecureFallbackApprovalException e) {
      Log.w(TAG, e);
      database.markAsPendingInsecureSmsFallback(record.getId());
      MessageNotifier.notifyMessageDeliveryFailed(context, record.getRecipients(), record.getThreadId());
      ApplicationContext.getInstance(context).getJobManager().add(new DirectoryRefreshJob(context));
    } catch (UntrustedIdentityException e) {
      Log.w(TAG, e);
      Recipients recipients  = RecipientFactory.getRecipientsFromString(context, e.getE164Number(), false);
      long       recipientId = recipients.getPrimaryRecipient().getRecipientId();

      database.addMismatchedIdentity(record.getId(), recipientId, e.getIdentityKey());
      database.markAsSentFailed(record.getId());
      database.markAsPush(record.getId());
    }
  }

  @Override
  public boolean onShouldRetryThrowable(Exception exception) {
    if (exception instanceof RetryLaterException) return true;

    return false;
  }

  @Override
  public void onCanceled() {
    DatabaseFactory.getSmsDatabase(context).markAsSentFailed(messageId);

    long       threadId   = DatabaseFactory.getSmsDatabase(context).getThreadIdForMessage(messageId);
    Recipients recipients = DatabaseFactory.getThreadDatabase(context).getRecipientsForThreadId(threadId);

    if (threadId != -1 && recipients != null) {
      MessageNotifier.notifyMessageDeliveryFailed(context, recipients, threadId);
    }
  }

  private void deliver(SmsMessageRecord message)
      throws UntrustedIdentityException, InsecureFallbackApprovalException, RetryLaterException
  {
    try {
      SignalServiceAddress       address           = getPushAddress(message.getIndividualRecipient().getNumber());
      SignalServiceMessageSender messageSender     = messageSenderFactory.create();
      SignalServiceDataMessage   textSecureMessage = SignalServiceDataMessage.newBuilder()
                                                                             .withTimestamp(message.getDateSent())
                                                                             .withBody(message.getBody().getBody())
                                                                             .withExpiration((int)(message.getExpiresIn() / 1000))
                                                                             .asEndSessionMessage(message.isEndSession())
                                                                             .build();


      messageSender.sendMessage(address, textSecureMessage);
    } catch (InvalidNumberException | UnregisteredUserException e) {
      Log.w(TAG, e);
      throw new InsecureFallbackApprovalException(e);
    } catch (IOException e) {
      Log.w(TAG, e);
      throw new RetryLaterException(e);
    }
  }
}
